use crate::LicenseError;

const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const PREFIX: &str = "VK1-";
const BEGIN: &str = "-----BEGIN VOUCHKIT LICENSE-----";
const END: &str = "-----END VOUCHKIT LICENSE-----";
pub(crate) const MAX_TOKEN_BYTES: usize = 1_100;
/// Maximum size of a license token's textual representation, including separators.
pub const MAX_TOKEN_TEXT: usize = 4_096;

fn symbols(bytes: &[u8]) -> impl Iterator<Item = u8> + '_ {
    let complete = bytes.len().saturating_mul(8) / 5;
    let total = bytes.len().saturating_mul(8).div_ceil(5);
    (0..total).filter_map(move |symbol| {
        let offset = symbol * 5;
        let byte = offset / 8;
        let shift = 11 - offset % 8;
        let high = u16::from(*bytes.get(byte)?) << 8;
        let low = u16::from(bytes.get(byte + 1).copied().unwrap_or_default());
        let bits = if symbol < complete { high | low } else { high };
        ALPHABET.get(usize::from((bits >> shift) & 31)).copied()
    })
}

/// Encodes binary license data as grouped, unpadded Crockford Base32.
pub fn encode_token(bytes: &[u8]) -> String {
    let mut out = String::from(PREFIX);
    for (index, value) in symbols(bytes).enumerate() {
        if index != 0 && index % 5 == 0 {
            out.push('-');
        }
        out.push(char::from(value));
    }
    out
}

/// Encodes binary license data as a labeled and line-wrapped license document.
pub fn encode_license_file(bytes: &[u8]) -> String {
    let mut out = format!("{BEGIN}\n");
    for (index, value) in PREFIX.bytes().chain(symbols(bytes)).enumerate() {
        if index != 0 && index % 64 == 0 {
            out.push('\n');
        }
        out.push(char::from(value));
    }
    out.push('\n');
    out.push_str(END);
    out.push('\n');
    out
}

/// Decodes a grouped text token or an armored license file.
///
/// # Errors
///
/// Rejects unrecognized syntax, nonzero trailing bits and over-limit inputs.
pub fn decode_token(text: &str) -> Result<Vec<u8>, LicenseError> {
    if text.len() > MAX_TOKEN_TEXT {
        return Err(LicenseError::Malformed);
    }
    let text = text.trim();
    let text = if let Some(body) = text.strip_prefix(BEGIN) {
        body.strip_suffix(END).ok_or(LicenseError::Malformed)?
    } else {
        text
    };
    let mut symbols = text.chars().filter(|ch| *ch != '-' && !ch.is_whitespace());
    if !matches!(
        (symbols.next(), symbols.next(), symbols.next()),
        (Some('V' | 'v'), Some('K' | 'k'), Some('1'))
    ) {
        return Err(LicenseError::Malformed);
    }
    let mut output = Vec::new();
    let mut remaining = 0u8;
    let mut accumulator = 0u16;
    let mut count = 0;
    for character in symbols {
        let value = match character.to_ascii_uppercase() {
            'O' => 0,
            'I' | 'L' => 1,
            ch => ALPHABET
                .iter()
                .position(|&candidate| char::from(candidate) == ch)
                .and_then(|index| u16::try_from(index).ok())
                .ok_or(LicenseError::Malformed)?,
        };
        count += 1;
        accumulator = (accumulator << 5) | value;
        remaining += 5;
        if remaining >= 8 {
            remaining -= 8;
            output.push(((accumulator >> remaining) & 255) as u8);
            accumulator &= (1 << remaining) - 1;
            if output.len() > MAX_TOKEN_BYTES {
                return Err(LicenseError::Malformed);
            }
        }
    }
    if accumulator != 0 || output.is_empty() || count != (output.len() * 8).div_ceil(5) {
        return Err(LicenseError::Malformed);
    }
    Ok(output)
}
