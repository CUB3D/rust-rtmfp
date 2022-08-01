pub fn checksum(bytes: &[u8]) -> u16 {
    let mut bytes = bytes.to_vec();
    if bytes.len() % 16 != 0 {
        bytes.push(0);
    }

    let simple_checksum: u32 = bytes
        .chunks(2)
        .map(|pair| {
            let first = pair[0] as u16;

            let val = if let Some(second) = pair.get(1).map(|v| *v as u16) {
                (first << 8) | second
            } else {
                first
            } as u32;

            val
        })
        .sum::<u32>();

    !((simple_checksum >> 16) as u16 + (simple_checksum & 0xFFFF) as u16)
}

#[cfg(test)]
mod test {
    use crate::checksum::checksum;

    #[test]
    #[ignore]
    fn case_1() {
        assert_eq!(
            checksum(&[11, 0, 0, 48, 0, 7, 2, 1, 10, 65, 66, 67, 68]),
            42495
        );
        assert_eq!(
            checksum(&[20, 232, 53, 221, 164, 148, 41, 249, 14, 18, 198, 211, 223, 126, 70]),
            12802
        );
    }

    #[test]
    fn case_2() {
        assert_eq!(
            checksum(&[11, 0, 0, 48, 0, 9, 2, 1, 10, 65, 66, 67, 68, 69, 70, 0]),
            7164
        );
        assert_eq!(
            checksum(&[11, 0, 0, 48, 0, 9, 2, 1, 10, 65, 66, 67, 68, 69, 70]),
            7164
        );
    }
}
