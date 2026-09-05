# sync-kit 0.4.1

Corrects the `apply` guard introduced in 0.4.0. Upgrade from 0.4.0 directly;
0.4.0's check rejects correct consumer implementations.

## The defect in 0.4.0

0.4.0 required the value returned by `apply` to have the *same* stable
fingerprint as the merged value. That is the wrong invariant.

`read` runs early in the serialized turn and `apply` runs after the network
write completes. Local state can legitimately change in between — that gap is
the apply window the whole API exists to address. A correct `apply` re-merges
the merged value with live local state inside the consumer's lock, so what it
commits is often *ahead* of `merged`.

Under the equality check, that correct implementation raised `state`, while the
lossy one — assigning `merged` verbatim under the lock, destroying every edit
made during the round trip — passed cleanly. The guard punished correctness and
rubber-stamped the bug it was meant to catch. The documented example was itself
the lossy pattern.

## The fix

The controller now checks **subsumption** rather than equality: merging
`merged` into the value `apply` returned must add nothing.

```ts
codec.fingerprint(codec.merge(merged, committed)) === codec.fingerprint(committed)
```

- An `apply` that folds in edits newer than `read` passes. The cloud is briefly
  behind local; the next sync's fingerprint comparison publishes the difference.
- An `apply` that drops part of the merge still raises `state`
  (`SyncKitErrorCode.STATE` on Android).
- A pass-through `apply` returning `merged` unchanged still passes, for
  consumers with no local mirror.

No signature changed. Consumers already on 0.4.0 that only ever commit `merged`
verbatim keep compiling — but that pattern is lossy and should be replaced with
a re-merge inside the lock.

## Correct shape

```ts
await controller.syncDataset("tasks", {
  read: () => store.tasks,
  apply: (merged) =>
    db.withTransaction(async () => {
      store.tasks = codec.merge(merged, store.tasks);
      return store.tasks;
    }),
});
```

## Documentation

`docs/consumer-responsibilities.md` — "The apply window" now shows the
re-merging example, states the subsumption rule, and calls out
`store.tasks = merged` explicitly as the mistake the API exists to prevent.
