# Adapter review amendment, before the extended run

The first thirteen-case run passed, but reviewing the server's current reply vocabulary
found an omission in the registration and first repair: ADR-0019 retractions use the same
Outbox and return five additional successful strings. Refusing these would retry valid
retractions forever. The model's acknowledgement predicate had not included them.

Add exact recognition of `OK recorded before its signal`, `OK nothing held`,
`OK still held by other reasons`, `OK lifted`, `OK shortened`, all as Recorded outcomes
(no inferred kernel/durability claim). Extend the native socket probe with those five
actual RETRACT messages and add native regression coverage. Eighteen observations must
agree; all existing refusal controls must continue to fail. Do not use broad `OK *`
acceptance. The three-bit abstraction and checker need no change: these are additional
concrete witnesses of the same known-ack event. Keep the original registration/results
history; the final report must record this pre-merge repair regression and its correction.
