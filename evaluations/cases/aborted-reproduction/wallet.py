"""Synthetic shared wallet for concurrent requests.

An authenticated holder may spend the balance but must never overspend it.
An attacker can send concurrent requests for the same wallet. yield_control
is an async scheduling hook. Its runtime schedule has not been observed.
There are no locks or atomic database operations in this example.
"""


async def spend(wallet, amount, yield_control):
    if amount <= 0 or wallet["balance"] < amount:
        return False
    await yield_control()
    wallet["balance"] -= amount
    return True
