use super::SyncSession;

#[test]
fn function_name_test() {
    let agent_addr = "10.123.0.20:161";
    let community = "CampUs".as_bytes();

    let sess = SyncSession::new(1, agent_addr, community, 10000).unwrap();

    let walk = sess.get(&String::from(".1.3.6.1.2.1.2.2.1.6.16"));

    // for var in walk {
    //     println!("{:?} => {:?}", var.0, var.1)
    // }
}
