use std::io::{self, Read};
use std::time::{Duration, Instant};

use core_runtime::http_client::Url;
use core_runtime::inbound::AnyStream;
use core_runtime::tls_client::wrap_probe_stream;
use flate2::read::GzDecoder;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

#[allow(dead_code)]
impl HttpResponse {
    pub fn header(&self, name: &str) -> Option<&str> {
        let lower = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(&lower))
            .map(|(_, v)| v.as_str())
    }

    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

const MAX_CHUNK_HEADER_LEN: usize = 1024;
const MAX_CONNECT_HEADER_LEN: usize = 8192;
const CLASH_MAX_BYTES: usize = 16 * 1024 * 1024;

fn format_host_port_for_http(host: &str, port: u16) -> String {
    let bare = host.trim_matches(|c| c == '[' || c == ']');
    if bare.contains(':') {
        format!("[{bare}]:{port}")
    } else {
        format!("{bare}:{port}")
    }
}

fn same_origin(a: &Url, b: &Url) -> bool {
    a.secure == b.secure && a.port == b.port && a.host.eq_ignore_ascii_case(&b.host)
}

async fn connect_stream(
    url: &Url,
    proxy_port: Option<u16>,
    timeout: Duration,
) -> io::Result<AnyStream> {
    let raw_host = url.host.trim_matches(|c| c == '[' || c == ']');
    if let Some(pport) = proxy_port {
        let mut tcp = tokio::time::timeout(timeout, TcpStream::connect(("127.0.0.1", pport)))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "proxy connect timeout"))??;
        let _ = tcp.set_nodelay(true);

        if url.secure {
            let hp = format_host_port_for_http(raw_host, url.port);
            let connect_req = format!(
                "CONNECT {hp} HTTP/1.1\r\nHost: {hp}\r\nProxy-Connection: Keep-Alive\r\n\r\n"
            );
            tokio::time::timeout(timeout, async {
                tcp.write_all(connect_req.as_bytes()).await?;
                tcp.flush().await
            })
            .await
            .map_err(|_| {
                io::Error::new(io::ErrorKind::TimedOut, "proxy CONNECT write timeout")
            })??;

            let mut hdr_buf = Vec::with_capacity(512);
            tokio::time::timeout(timeout, async {
                let mut b = [0u8; 1];
                loop {
                    let n = tcp.read(&mut b).await?;
                    if n == 0 {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "proxy closed during CONNECT",
                        ));
                    }
                    hdr_buf.push(b[0]);
                    if hdr_buf.ends_with(b"\r\n\r\n") {
                        return Ok(());
                    }
                    if hdr_buf.len() >= MAX_CONNECT_HEADER_LEN {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "proxy CONNECT headers too large",
                        ));
                    }
                }
            })
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "proxy CONNECT read timeout"))??;

            let status_line = String::from_utf8_lossy(&hdr_buf);
            if !status_line.starts_with("HTTP/1.1 200") && !status_line.starts_with("HTTP/1.0 200")
            {
                return Err(io::Error::other(format!(
                    "proxy CONNECT failed: {}",
                    status_line.lines().next().unwrap_or("bad status")
                )));
            }
            tokio::time::timeout(timeout, wrap_probe_stream(tcp, raw_host))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TLS handshake timeout"))?
        } else {
            Ok(Box::new(tcp))
        }
    } else {
        let tcp = tokio::time::timeout(timeout, TcpStream::connect((raw_host, url.port)))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TCP connect timeout"))??;
        let _ = tcp.set_nodelay(true);
        if url.secure {
            tokio::time::timeout(timeout, wrap_probe_stream(tcp, raw_host))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TLS handshake timeout"))?
        } else {
            Ok(Box::new(tcp))
        }
    }
}

async fn read_http_head(
    stream: &mut AnyStream,
) -> io::Result<(u16, Vec<(String, String)>, Vec<u8>)> {
    let mut buf = Vec::with_capacity(2048);
    let mut temp = [0u8; 1024];
    let header_end = loop {
        let n = stream.read(&mut temp).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "EOF before HTTP headers",
            ));
        }
        buf.extend_from_slice(&temp[..n]);
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos;
        }
        if buf.len() > 65536 {
            return Err(io::Error::other("HTTP headers too large"));
        }
    };

    let head_bytes = &buf[..header_end];
    let leftover = buf[header_end + 4..].to_vec();
    let head_str = String::from_utf8_lossy(head_bytes);
    let mut lines = head_str.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| io::Error::other(format!("invalid HTTP status line: {status_line}")))?;

    let mut headers = Vec::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
        }
    }

    Ok((status, headers, leftover))
}

async fn read_chunked_body<S: tokio::io::AsyncRead + Unpin>(
    stream: &mut S,
    mut leftover: Vec<u8>,
    max_bytes: usize,
) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();

    async fn ensure_bytes<S: tokio::io::AsyncRead + Unpin>(
        stream: &mut S,
        buf: &mut Vec<u8>,
        need: usize,
    ) -> io::Result<()> {
        let mut tmp = [0u8; 8192];
        while buf.len() < need {
            let n = stream.read(&mut tmp).await?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "EOF in chunked body",
                ));
            }
            buf.extend_from_slice(&tmp[..n]);
        }
        Ok(())
    }

    loop {
        let line_end = loop {
            if let Some(pos) = leftover.windows(2).position(|w| w == b"\r\n") {
                if pos > MAX_CHUNK_HEADER_LEN {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "chunk header line too long",
                    ));
                }
                break pos;
            }
            if leftover.len() > MAX_CHUNK_HEADER_LEN {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "chunk header line too long",
                ));
            }
            let prev = leftover.len();
            ensure_bytes(stream, &mut leftover, prev + 1).await?;
        };
        let size_str = String::from_utf8_lossy(&leftover[..line_end]);
        let size_hex = size_str.split(';').next().unwrap_or("").trim();
        let chunk_size = usize::from_str_radix(size_hex, 16).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid chunk size: {size_hex}"),
            )
        })?;
        leftover.drain(..line_end + 2);
        if chunk_size == 0 {
            break;
        }
        if chunk_size > max_bytes.saturating_sub(out.len()) {
            return Err(io::Error::other("HTTP response exceeds max size"));
        }
        let need_with_crlf = chunk_size
            .checked_add(2)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "chunk size overflow"))?;
        ensure_bytes(stream, &mut leftover, need_with_crlf).await?;
        out.extend_from_slice(&leftover[..chunk_size]);
        leftover.drain(..need_with_crlf);
    }

    Ok(out)
}

fn decode_gzip_capped(raw_body: &[u8], max_bytes: usize) -> io::Result<Vec<u8>> {
    let mut dec = GzDecoder::new(raw_body).take((max_bytes as u64).saturating_add(1));
    let mut out = Vec::new();
    dec.read_to_end(&mut out)?;
    if out.len() > max_bytes {
        return Err(io::Error::other("decompressed HTTP body exceeds max size"));
    }
    Ok(out)
}

pub async fn fetch_url(
    raw_url: &str,
    method: &str,
    extra_headers: &[(&str, &str)],
    body: Option<&[u8]>,
    proxy_port: Option<u16>,
    timeout: Duration,
) -> io::Result<HttpResponse> {
    fetch_url_with_progress(
        raw_url,
        method,
        extra_headers,
        body,
        proxy_port,
        timeout,
        |_, _| {},
    )
    .await
}

pub async fn fetch_url_with_progress<F>(
    raw_url: &str,
    method: &str,
    extra_headers: &[(&str, &str)],
    body: Option<&[u8]>,
    proxy_port: Option<u16>,
    timeout: Duration,
    mut on_progress: F,
) -> io::Result<HttpResponse>
where
    F: FnMut(usize, Option<usize>),
{
    let initial_url = Url::parse(raw_url)?;
    let mut current = initial_url.clone();
    let mut cur_method = method.to_string();
    let mut cur_body = body.map(|b| b.to_vec());

    for _ in 0..8 {
        let mut stream = connect_stream(&current, proxy_port, timeout).await?;
        let req_path = if proxy_port.is_some() && !current.secure {
            format!("http://{}{}", current.authority(), current.path)
        } else {
            current.path.clone()
        };

        let mut req = format!(
            "{} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nAccept-Encoding: gzip, identity\r\n",
            cur_method,
            req_path,
            current.authority()
        );
        let mut has_ua = false;
        let send_auth = same_origin(&current, &initial_url);
        for (k, v) in extra_headers {
            if !send_auth && k.eq_ignore_ascii_case("authorization") {
                continue;
            }
            if k.eq_ignore_ascii_case("user-agent") {
                has_ua = true;
            }
            req.push_str(&format!("{k}: {v}\r\n"));
        }
        if !has_ua {
            req.push_str("User-Agent: Tachyon-Client/1.0\r\n");
        }
        if let Some(ref b) = cur_body {
            req.push_str(&format!("Content-Length: {}\r\n", b.len()));
        }
        req.push_str("\r\n");

        tokio::time::timeout(timeout, async {
            stream.write_all(req.as_bytes()).await?;
            if let Some(ref b) = cur_body {
                stream.write_all(b).await?;
            }
            stream.flush().await
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "HTTP request write timeout"))??;

        let (status, headers, mut leftover) =
            tokio::time::timeout(timeout, read_http_head(&mut stream))
                .await
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::TimedOut, "HTTP header read timeout")
                })??;

        if matches!(status, 301 | 302 | 303 | 307 | 308)
            && let Some((_, loc)) = headers.iter().find(|(k, _)| k == "location")
        {
            current = current.join(loc)?;
            if status == 303 || (status == 302 && cur_method.eq_ignore_ascii_case("POST")) {
                cur_method = "GET".to_string();
                cur_body = None;
            }
            continue;
        }

        let no_body = cur_method.eq_ignore_ascii_case("HEAD")
            || (100..200).contains(&status)
            || status == 204
            || status == 304;

        let is_chunked = headers
            .iter()
            .any(|(k, v)| k == "transfer-encoding" && v.to_ascii_lowercase().contains("chunked"));
        let content_len = headers
            .iter()
            .find(|(k, _)| k == "content-length")
            .and_then(|(_, v)| v.parse::<usize>().ok());

        let max_bytes = 96 * 1024 * 1024;
        let raw_body = if no_body {
            Vec::new()
        } else if is_chunked {
            tokio::time::timeout(timeout, read_chunked_body(&mut stream, leftover, max_bytes))
                .await
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::TimedOut, "HTTP chunked read timeout")
                })??
        } else if let Some(len) = content_len {
            if len > max_bytes {
                return Err(io::Error::other("HTTP body too large"));
            }
            on_progress(leftover.len().min(len), Some(len));
            let mut last_tick = Instant::now();
            while leftover.len() < len {
                let mut tmp = [0u8; 16384];
                let to_read = (len - leftover.len()).min(tmp.len());
                let n = tokio::time::timeout(timeout, stream.read(&mut tmp[..to_read]))
                    .await
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::TimedOut, "HTTP body read timeout")
                    })??;
                if n == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "EOF before HTTP Content-Length",
                    ));
                }
                leftover.extend_from_slice(&tmp[..n]);
                if last_tick.elapsed() >= Duration::from_millis(120) {
                    on_progress(leftover.len().min(len), Some(len));
                    last_tick = Instant::now();
                }
            }
            leftover.truncate(len);
            on_progress(leftover.len(), Some(len));
            leftover
        } else {
            let mut tmp = [0u8; 16384];
            let mut last_tick = Instant::now();
            loop {
                match tokio::time::timeout(timeout, stream.read(&mut tmp)).await {
                    Ok(Ok(0)) => break,
                    Ok(Ok(n)) => {
                        if n > max_bytes.saturating_sub(leftover.len()) {
                            return Err(io::Error::other("HTTP response exceeds max size"));
                        }
                        leftover.extend_from_slice(&tmp[..n]);
                        if last_tick.elapsed() >= Duration::from_millis(120) {
                            on_progress(leftover.len(), None);
                            last_tick = Instant::now();
                        }
                    }
                    Ok(Err(e)) => return Err(e),
                    Err(_) => {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "HTTP body read timeout",
                        ));
                    }
                }
            }
            leftover
        };

        let is_gzip = headers
            .iter()
            .any(|(k, v)| k == "content-encoding" && v.to_ascii_lowercase().contains("gzip"));
        let final_body = if is_gzip && !raw_body.is_empty() {
            decode_gzip_capped(&raw_body, max_bytes)?
        } else {
            raw_body
        };

        return Ok(HttpResponse {
            status,
            headers,
            body: final_body,
        });
    }

    Err(io::Error::other("too many redirects"))
}

pub async fn clash_api_request(
    port: u16,
    secret: &str,
    method: &str,
    path: &str,
    body: Option<&str>,
) -> io::Result<(u16, String)> {
    let mut tcp = tokio::time::timeout(
        Duration::from_secs(4),
        TcpStream::connect(("127.0.0.1", port)),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "clash api connect timeout"))??;
    let _ = tcp.set_nodelay(true);

    let body_bytes = body.unwrap_or("").as_bytes();
    let req = if body.is_some() {
        format!(
            "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nAuthorization: Bearer {secret}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body_bytes.len()
        )
    } else {
        format!(
            "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nAuthorization: Bearer {secret}\r\nConnection: close\r\n\r\n"
        )
    };

    tokio::time::timeout(Duration::from_secs(4), async {
        tcp.write_all(req.as_bytes()).await?;
        if !body_bytes.is_empty() {
            tcp.write_all(body_bytes).await?;
        }
        tcp.flush().await
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "clash api write timeout"))??;

    let mut boxed: AnyStream = Box::new(tcp);
    let (status, headers, mut leftover) =
        tokio::time::timeout(Duration::from_secs(6), read_http_head(&mut boxed))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "clash api read timeout"))??;

    if method.eq_ignore_ascii_case("HEAD")
        || (100..200).contains(&status)
        || status == 204
        || status == 304
    {
        return Ok((status, String::new()));
    }

    let is_chunked = headers
        .iter()
        .any(|(k, v)| k == "transfer-encoding" && v.to_ascii_lowercase().contains("chunked"));
    let content_len = headers
        .iter()
        .find(|(k, _)| k == "content-length")
        .and_then(|(_, v)| v.parse::<usize>().ok());

    let raw_body = if is_chunked {
        tokio::time::timeout(
            Duration::from_secs(6),
            read_chunked_body(&mut boxed, leftover, CLASH_MAX_BYTES),
        )
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "clash api chunked read timeout"))??
    } else if let Some(len) = content_len {
        if len > CLASH_MAX_BYTES {
            return Err(io::Error::other("clash api response exceeds max size"));
        }
        while leftover.len() < len {
            let mut tmp = [0u8; 4096];
            let to_read = (len - leftover.len()).min(tmp.len());
            let n = tokio::time::timeout(Duration::from_secs(6), boxed.read(&mut tmp[..to_read]))
                .await
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::TimedOut, "clash api body read timeout")
                })??;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "clash api EOF before Content-Length",
                ));
            }
            leftover.extend_from_slice(&tmp[..n]);
        }
        leftover.truncate(len);
        leftover
    } else {
        let mut tmp = [0u8; 4096];
        loop {
            match tokio::time::timeout(Duration::from_secs(2), boxed.read(&mut tmp)).await {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => {
                    if n > CLASH_MAX_BYTES.saturating_sub(leftover.len()) {
                        return Err(io::Error::other("clash api response exceeds max size"));
                    }
                    leftover.extend_from_slice(&tmp[..n]);
                }
                Ok(Err(e)) => return Err(e),
                Err(_) => break,
            }
        }
        leftover
    };

    Ok((status, String::from_utf8_lossy(&raw_body).into_owned()))
}

pub struct SpeedtestOutcome {
    pub mbps: f64,
    pub mbs: f64,
    pub peak_mbps: f64,
    pub ttfb_ms: u64,
    pub total_bytes: u64,
    pub downloaded_mb: f64,
    pub target_mb: u32,
    pub server: String,
    pub stopped: bool,
}

async fn with_cancel<T, Fut>(
    cancel_rx: &mut tokio::sync::watch::Receiver<bool>,
    fut: Fut,
) -> Result<T, bool>
where
    Fut: std::future::Future<Output = T>,
{
    tokio::pin!(fut);
    loop {
        if *cancel_rx.borrow() {
            return Err(true);
        }
        tokio::select! {
            res = &mut fut => return Ok(res),
            changed = cancel_rx.changed() => {
                if changed.is_err() || *cancel_rx.borrow() {
                    return Err(true);
                }
            }
        }
    }
}

pub async fn run_speedtest_stream<F>(
    candidates: &[(&str, &str)],
    size_mb: u32,
    proxy_port: Option<u16>,
    mut cancel_rx: tokio::sync::watch::Receiver<bool>,
    mut on_progress: F,
) -> io::Result<SpeedtestOutcome>
where
    F: FnMut(serde_json::Value),
{
    let target_bytes = (size_mb as u64) * 1024 * 1024;
    let mut chosen_url: Option<Url> = None;
    let mut chosen_label = String::new();
    let mut active_stream: Option<(AnyStream, Vec<u8>)> = None;
    let mut ttfb_ms = 1u64;

    for (raw_url, label) in candidates {
        if *cancel_rx.borrow() {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "Тест остановлен",
            ));
        }
        let Ok(mut cur_url) = Url::parse(raw_url) else {
            continue;
        };
        let sw_ttfb = Instant::now();
        let mut ok_conn = None;

        for _ in 0..4 {
            let mut st = match with_cancel(
                &mut cancel_rx,
                connect_stream(&cur_url, proxy_port, Duration::from_secs(6)),
            )
            .await
            {
                Ok(Ok(s)) => s,
                Ok(Err(_)) => break,
                Err(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "Тест остановлен",
                    ));
                }
            };
            let req_path = if proxy_port.is_some() && !cur_url.secure {
                format!("http://{}{}", cur_url.authority(), cur_url.path)
            } else {
                cur_url.path.clone()
            };
            let req = format!(
                "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: Mozilla/5.0 Chrome/124.0.0.0\r\nAccept: */*\r\nConnection: close\r\n\r\n",
                req_path,
                cur_url.authority()
            );
            let write_res = with_cancel(&mut cancel_rx, async {
                tokio::time::timeout(Duration::from_secs(4), st.write_all(req.as_bytes())).await
            })
            .await;
            match write_res {
                Ok(Ok(Ok(()))) => {}
                Ok(_) => break,
                Err(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "Тест остановлен",
                    ));
                }
            }

            let head_res = with_cancel(
                &mut cancel_rx,
                tokio::time::timeout(Duration::from_secs(6), read_http_head(&mut st)),
            )
            .await;
            let (status, headers, leftover) = match head_res {
                Ok(Ok(Ok(h))) => h,
                Ok(_) => break,
                Err(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "Тест остановлен",
                    ));
                }
            };
            if matches!(status, 301 | 302 | 303 | 307 | 308) {
                if let Some((_, loc)) = headers.iter().find(|(k, _)| k == "location")
                    && let Ok(next_u) = cur_url.join(loc)
                {
                    cur_url = next_u;
                    continue;
                }
                break;
            }
            if (200..300).contains(&status) {
                ok_conn = Some((st, leftover));
            }
            break;
        }

        if let Some(conn) = ok_conn {
            ttfb_ms = sw_ttfb.elapsed().as_millis().max(1) as u64;
            chosen_url = Some(cur_url);
            chosen_label = (*label).to_string();
            active_stream = Some(conn);
            break;
        }
    }

    let Some(url) = chosen_url else {
        return Err(io::Error::other("Ни один тестовый сервер не ответил"));
    };

    let mut total_bytes = 0u64;
    let mut peak_mbps = 0.0f64;
    let dl_sw = Instant::now();
    let mut last_report_ms = 0u64;
    let mut window_bytes = 0u64;
    let mut window_start_ms = 0u64;
    let mut stopped_early = false;
    let mut buf = vec![0u8; 65536];

    while total_bytes < target_bytes {
        if *cancel_rx.borrow() {
            stopped_early = true;
            break;
        }

        if active_stream.is_none() {
            let mut st = match with_cancel(
                &mut cancel_rx,
                connect_stream(&url, proxy_port, Duration::from_secs(6)),
            )
            .await
            {
                Ok(Ok(s)) => s,
                Ok(Err(_)) => break,
                Err(_) => {
                    stopped_early = true;
                    break;
                }
            };
            let req_path = if proxy_port.is_some() && !url.secure {
                format!("http://{}{}", url.authority(), url.path)
            } else {
                url.path.clone()
            };
            let req = format!(
                "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: Mozilla/5.0 Chrome/124.0.0.0\r\nAccept: */*\r\nConnection: close\r\n\r\n",
                req_path,
                url.authority()
            );
            match with_cancel(&mut cancel_rx, async {
                tokio::time::timeout(Duration::from_secs(4), st.write_all(req.as_bytes())).await
            })
            .await
            {
                Ok(Ok(Ok(()))) => {}
                Ok(_) => break,
                Err(_) => {
                    stopped_early = true;
                    break;
                }
            }
            let (status, _, leftover) = match with_cancel(
                &mut cancel_rx,
                tokio::time::timeout(Duration::from_secs(6), read_http_head(&mut st)),
            )
            .await
            {
                Ok(Ok(Ok(h))) => h,
                Ok(_) => break,
                Err(_) => {
                    stopped_early = true;
                    break;
                }
            };
            if !(200..300).contains(&status) {
                break;
            }
            active_stream = Some((st, leftover));
        }

        let (mut st, leftover) = active_stream.take().unwrap();
        let mut stream_read = 0u64;
        if !leftover.is_empty() {
            let take = (leftover.len() as u64).min(target_bytes - total_bytes);
            total_bytes += take;
            stream_read += take;
            window_bytes += take;
        }

        while total_bytes < target_bytes {
            let to_read = (buf.len() as u64).min(target_bytes - total_bytes) as usize;
            let read_res = tokio::select! {
                _ = cancel_rx.changed() => {
                    if *cancel_rx.borrow() {
                        stopped_early = true;
                        break;
                    }
                    continue;
                }
                r = tokio::time::timeout(Duration::from_secs(10), st.read(&mut buf[..to_read])) => r,
            };

            let n = match read_res {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => n,
                _ => break,
            };

            total_bytes += n as u64;
            stream_read += n as u64;
            window_bytes += n as u64;

            let elapsed_ms = dl_sw.elapsed().as_millis() as u64;
            if elapsed_ms.saturating_sub(last_report_ms) >= 200 {
                let sec_total = dl_sw.elapsed().as_secs_f64().max(0.05);
                let cur_mbps = (((total_bytes as f64) * 8.0) / (sec_total * 1_000_000.0) * 10.0)
                    .round()
                    / 10.0;
                let cur_mbs = (((total_bytes as f64) / (1024.0 * 1024.0)) / sec_total * 100.0)
                    .round()
                    / 100.0;

                let win_dt = elapsed_ms.saturating_sub(window_start_ms);
                if win_dt >= 250 {
                    let inst_mbps = (((window_bytes as f64) * 8.0)
                        / ((win_dt as f64 / 1000.0) * 1_000_000.0)
                        * 10.0)
                        .round()
                        / 10.0;
                    if inst_mbps > peak_mbps {
                        peak_mbps = inst_mbps;
                    }
                    window_bytes = 0;
                    window_start_ms = elapsed_ms;
                }
                if cur_mbps > peak_mbps {
                    peak_mbps = cur_mbps;
                }
                last_report_ms = elapsed_ms;
                let pct = ((total_bytes * 100) / target_bytes.max(1)).clamp(1, 99);
                let dl_mb = (((total_bytes as f64) / (1024.0 * 1024.0)) * 10.0).round() / 10.0;
                on_progress(serde_json::json!({
                    "mbps": cur_mbps,
                    "mbs": cur_mbs,
                    "peakMbps": peak_mbps,
                    "ttfbMs": ttfb_ms,
                    "downloadedMb": dl_mb,
                    "targetMb": size_mb,
                    "percent": pct,
                    "server": chosen_label,
                }));
            }
        }

        if stopped_early || stream_read == 0 {
            break;
        }
    }

    if total_bytes == 0 {
        return Err(io::Error::other(if stopped_early {
            "Тест остановлен"
        } else {
            "Не удалось получить поток данных"
        }));
    }

    let sec = dl_sw.elapsed().as_secs_f64().max(0.1);
    let mbps = (((total_bytes as f64) * 8.0) / (sec * 1_000_000.0) * 10.0).round() / 10.0;
    let mbs = (((total_bytes as f64) / (1024.0 * 1024.0)) / sec * 100.0).round() / 100.0;
    if mbps > peak_mbps {
        peak_mbps = mbps;
    }
    let downloaded_mb = (((total_bytes as f64) / (1024.0 * 1024.0)) * 10.0).round() / 10.0;

    Ok(SpeedtestOutcome {
        mbps,
        mbs,
        peak_mbps,
        ttfb_ms,
        total_bytes,
        downloaded_mb,
        target_mb: size_mb,
        server: chosen_label,
        stopped: stopped_early,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{Compression, write::GzEncoder};
    use std::io::Write;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn read_chunked_rejects_usize_overflow_and_huge_header() {
        let mut cursor = io::Cursor::new(b"ffffffffffffffff\r\nabc\r\n0\r\n\r\n".to_vec());
        let err = read_chunked_body(&mut cursor, Vec::new(), 1024)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("max size") || err.to_string().contains("overflow"));

        let long_hdr = vec![b'1'; MAX_CHUNK_HEADER_LEN + 10];
        let mut cur2 = io::Cursor::new(long_hdr);
        let err2 = read_chunked_body(&mut cur2, Vec::new(), 1024)
            .await
            .unwrap_err();
        assert_eq!(err2.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn decode_gzip_capped_blocks_bomb() {
        let mut enc = GzEncoder::new(Vec::new(), Compression::fast());
        enc.write_all(&vec![b'A'; 4096]).unwrap();
        let compressed = enc.finish().unwrap();

        assert!(decode_gzip_capped(&compressed, 512).is_err());
        let ok = decode_gzip_capped(&compressed, 4096).unwrap();
        assert_eq!(ok.len(), 4096);
    }

    #[tokio::test]
    async fn fetch_url_handles_204_and_eof_and_strips_auth_on_redirect() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr1 = listener.local_addr().unwrap();

        let listener2 = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr2 = listener2.local_addr().unwrap();

        tokio::spawn(async move {
            // 1) 204 No Content
            {
                let (mut s, _) = listener.accept().await.unwrap();
                let mut buf = [0u8; 1024];
                let _ = s.read(&mut buf).await;
                let _ = s.write_all(b"HTTP/1.1 204 No Content\r\n\r\n").await;
            }

            // 2) Truncated Content-Length
            {
                let (mut s, _) = listener.accept().await.unwrap();
                let mut buf = [0u8; 1024];
                let _ = s.read(&mut buf).await;
                let _ = s
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nhi")
                    .await;
            }

            // 3) Cross-port redirect to listener2
            {
                let (mut s, _) = listener.accept().await.unwrap();
                let mut buf = [0u8; 1024];
                let _ = s.read(&mut buf).await;
                let resp = format!(
                    "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{}/next\r\n\r\n",
                    addr2.port()
                );
                let _ = s.write_all(resp.as_bytes()).await;
            }
        });

        tokio::spawn(async move {
            let (mut s, _) = listener2.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let n = s.read(&mut buf).await.unwrap_or(0);
            let req_str = String::from_utf8_lossy(&buf[..n]);
            let has_auth = req_str.to_ascii_lowercase().contains("authorization:");
            let body = if has_auth { "leaked" } else { "clean" };
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = s.write_all(resp.as_bytes()).await;
        });

        let r1 = fetch_url(
            &format!("http://127.0.0.1:{}/empty", addr1.port()),
            "GET",
            &[],
            None,
            None,
            Duration::from_secs(2),
        )
        .await
        .unwrap();
        assert_eq!(r1.status, 204);
        assert!(r1.body.is_empty());

        let r2 = fetch_url(
            &format!("http://127.0.0.1:{}/trunc", addr1.port()),
            "GET",
            &[],
            None,
            None,
            Duration::from_secs(2),
        )
        .await
        .unwrap_err();
        assert_eq!(r2.kind(), io::ErrorKind::UnexpectedEof);

        let r3 = fetch_url(
            &format!("http://127.0.0.1:{}/redir", addr1.port()),
            "GET",
            &[("Authorization", "Bearer topsecret")],
            None,
            None,
            Duration::from_secs(2),
        )
        .await
        .unwrap();
        assert_eq!(r3.text(), "clean");
    }
}
