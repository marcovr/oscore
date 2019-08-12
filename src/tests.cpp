#define CATCH_CONFIG_MAIN
#include <catch/catch.hpp>

extern "C" {
    #include "edhoc_test.h"
    #include "cose_test.h"
    #include "oscore_test.h"
}

TEST_CASE("EDHOC test", "[EDHOC]") {
    REQUIRE(edhoc_test() == 0);
}

TEST_CASE("COSE test", "[COSE]") {
    REQUIRE(cose_test() == 0);
}

TEST_CASE("OSCORE context test", "[OSCORE]") {
    REQUIRE(oscore_context_test_1() == 0);
    REQUIRE(oscore_context_test_2() == 0);
    REQUIRE(oscore_context_test_3() == 0);
}

TEST_CASE("OSCORE request test", "[OSCORE]") {
    REQUIRE(oscore_request_test_1() == 0);
}
