ips =
{
    enable_builtin_rules = true,
    rules = [[
        include /Users/deankalweit/snort-test/rules/local.rules
    ]]
}

alert_fast =
{
    file = true,
    packet = false,
}
