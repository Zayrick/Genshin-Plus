pub struct Signature {
    bytes: Vec<Option<u8>>,
}

impl Signature {
    pub fn parse(signature: &str) -> Result<Self, String> {
        let mut bytes = Vec::new();
        for token in signature.split_whitespace() {
            if token == "?" || token == "??" {
                bytes.push(None);
                continue;
            }
            let b = u8::from_str_radix(token, 16)
                .map_err(|_| format!("invalid signature byte: {token}"))?;
            bytes.push(Some(b));
        }
        if bytes.is_empty() {
            return Err("empty signature".to_string());
        }
        Ok(Self { bytes })
    }

    pub fn scan(&self, haystack: &[u8]) -> Option<usize> {
        if self.bytes.len() > haystack.len() {
            return None;
        }
        let last = haystack.len() - self.bytes.len();
        'outer: for i in 0..=last {
            for (j, want) in self.bytes.iter().enumerate() {
                if let Some(want) = want {
                    if haystack[i + j] != *want {
                        continue 'outer;
                    }
                }
            }
            return Some(i);
        }
        None
    }

    pub fn scan_all(&self, haystack: &[u8], max: usize) -> Vec<usize> {
        let mut out = Vec::new();
        if self.bytes.len() > haystack.len() || max == 0 {
            return out;
        }
        let mut i = 0usize;
        while i + self.bytes.len() <= haystack.len() {
            if let Some(found) = self.scan(&haystack[i..]) {
                let pos = i + found;
                out.push(pos);
                if out.len() >= max {
                    break;
                }
                i = pos + 1;
            } else {
                break;
            }
        }
        out
    }
}
