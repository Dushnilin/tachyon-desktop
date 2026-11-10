use gpui::Rgba;

#[inline]
pub fn rgb_hex(hex: u32) -> Rgba {
    gpui::rgb(hex)
}

#[inline]
pub fn rgba_hex(hex: u32) -> Rgba {
    gpui::rgba(hex)
}

#[derive(Clone, Copy, Debug)]
pub struct Theme {
    pub is_light: bool,
    pub bg: Rgba,
    pub bg_card: Rgba,
    pub bg_elev: Rgba,
    pub bg_hover: Rgba,
    pub bg_glass: Rgba,
    pub border: Rgba,
    pub border_hi: Rgba,
    pub text: Rgba,
    pub text_soft: Rgba,
    pub text_dim: Rgba,
    pub text_mute: Rgba,
    pub accent: Rgba,
    pub accent_2: Rgba,
    pub accent_bg: Rgba,
    pub accent_border: Rgba,
    pub green: Rgba,
    pub green_bg: Rgba,
    pub green_border: Rgba,
    pub amber: Rgba,
    pub amber_bg: Rgba,
    pub amber_border: Rgba,
    pub red: Rgba,
    pub red_bg: Rgba,
    pub red_border: Rgba,
}

impl Theme {
    pub fn dark() -> Self {
        Self {
            is_light: false,
            bg: rgb_hex(0x0B0B0D),
            bg_card: rgb_hex(0x121216),
            bg_elev: rgb_hex(0x18181E),
            bg_hover: rgb_hex(0x1F1F27),
            bg_glass: rgba_hex(0x121216E0),
            border: rgba_hex(0xFFFFFF12),
            border_hi: rgba_hex(0xFFFFFF24),
            text: rgb_hex(0xF2F2F5),
            text_soft: rgb_hex(0xC2C2CC),
            text_dim: rgb_hex(0x8A8A96),
            text_mute: rgb_hex(0x52525E),
            accent: rgb_hex(0xB9A8FF),
            accent_2: rgb_hex(0x9179F2),
            accent_bg: rgba_hex(0xB9A8FF1C),
            accent_border: rgba_hex(0xB9A8FF59),
            green: rgb_hex(0x4CC38A),
            green_bg: rgba_hex(0x4CC38A1C),
            green_border: rgba_hex(0x4CC38A59),
            amber: rgb_hex(0xF5A623),
            amber_bg: rgba_hex(0xF5A6231C),
            amber_border: rgba_hex(0xF5A62359),
            red: rgb_hex(0xE5484D),
            red_bg: rgba_hex(0xE5484D1F),
            red_border: rgba_hex(0xE5484D59),
        }
    }

    pub fn light() -> Self {
        Self {
            is_light: true,
            bg: rgb_hex(0xF6F6F4),
            bg_card: rgb_hex(0xFFFFFF),
            bg_elev: rgb_hex(0xEFEFEC),
            bg_hover: rgb_hex(0xE6E6E2),
            bg_glass: rgba_hex(0xFFFFFFE8),
            border: rgba_hex(0x12121617),
            border_hi: rgba_hex(0x1212162E),
            text: rgb_hex(0x141418),
            text_soft: rgb_hex(0x363640),
            text_dim: rgb_hex(0x686873),
            text_mute: rgb_hex(0x9898A3),
            accent: rgb_hex(0x5B3FD6),
            accent_2: rgb_hex(0x472CB8),
            accent_bg: rgba_hex(0x5B3FD617),
            accent_border: rgba_hex(0x5B3FD64D),
            green: rgb_hex(0x18794E),
            green_bg: rgba_hex(0x18794E17),
            green_border: rgba_hex(0x18794E47),
            amber: rgb_hex(0xB4690E),
            amber_bg: rgba_hex(0xB4690E17),
            amber_border: rgba_hex(0xB4690E47),
            red: rgb_hex(0xCD2B31),
            red_bg: rgba_hex(0xCD2B3117),
            red_border: rgba_hex(0xCD2B3147),
        }
    }

    pub fn for_mode(light: bool) -> Self {
        if light {
            Self::light()
        } else {
            Self::dark()
        }
    }
}
