#[test]
fn test_reg_strs() {
    let mut count = 0;
    for reg in iced_x86::Register::values() {
        let reg_str = format!("{:?}", reg);
        count += 1;

        if reg != iced_x86::Register::None {
            println!("{}", reg_str);
            assert_eq!(reg, xgadget::str_to_reg(&reg_str).unwrap());
        }
    }
    assert_eq!(count, 249);
}
