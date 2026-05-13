from osi import infer_osi_layer, validate_event


def test_osi_layer_app():
    assert infer_osi_layer({"http_method": "GET", "url": "/"}) == 7


def test_osi_layer_session():
    assert infer_osi_layer({"session_id": "abc", "ssh_banner": "OpenSSH_8.2"}) == 5


def test_osi_layer_transport():
    assert infer_osi_layer({"src_ip": "1.1.1.1", "dst_ip": "2.2.2.2", "src_port": 22, "dst_port": 80}) == 4


def test_osi_validate_transport():
    assert validate_event({"src_ip": "1.1.1.1", "dst_ip": "2.2.2.2", "src_port": 22, "dst_port": 80})
