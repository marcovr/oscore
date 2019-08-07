#define CATCH_CONFIG_MAIN
#include <catch/catch.hpp>

extern "C" {
    #include "edhoc_test.h"
}

TEST_CASE("EDHOC test", "[EDHOC]") {
    REQUIRE(edhoc_test() == 0);
}
