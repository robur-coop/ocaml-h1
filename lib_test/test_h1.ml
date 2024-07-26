let () =
  Alcotest.run "httpaf unit tests"
    [ "iovec"            , Test_iovec.tests
    ; "request"          , Test_request.tests
    ; "response"         , Test_response.tests
    ; "client connection", Test_client_connection.tests
    ; "server connection", Test_server_connection.tests
    ]
