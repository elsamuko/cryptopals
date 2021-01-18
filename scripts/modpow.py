#!/usr/bin/env python3
# https://rosettacode.org/wiki/Modular_exponentiation#Python


def power_mod(base, power, modulo):
    " Without using builtin function "
    x = 1

    print('modulo= 0x%x' % modulo)
    print('base  = 0x%x' % base)
    print('power = 0x%x' % power)
    print('x     = 0x%x' % x)
    print('')

    while power > 0:
        base, power, x = (
            base * base % modulo,
            power // 2,
            base * x % modulo if power % 2 else x
        )
        print('base  = 0x%x' % base)
        print('power = 0x%x' % power)
        print('x     = 0x%x' % x)
        print('')

    return x


a = 2988348162058574136915891421498819466320163312926952423791023078876139
b = 2351399303373464486466122544523690094744975233415544072992656881240319
m = 10 ** 40

print('%x' % power_mod(a, b, m))
# print(power_mod(2, 11, 111))
# print('%x' % power_mod(2, 10, 100))
