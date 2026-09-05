# sync-kit 0.4.0

> **Superseded by 0.4.1.** The `apply` fingerprint check described below used
> equality, which rejects a correct re-merging `apply`. See
> `docs/release-notes-v0.4.1.md`.

`syncDataset` takes read/apply hooks instead of a value, on Web and Android.

## Breaking change

`SharedBackupController.syncDataset(datasetId, localValue)` is replaced by
`syncDataset(datasetId, mutator)`, where `mutator` supplies:

- `read()` — invoked inside the controller's serialized turn, immediately
  before the merge.
- `apply(merged)` — invoked with the merged value, and must return what was
  actually committed.

There is no deprecated value-taking overload. With a single shipped consumer,
carrying one would have made the unsafe form permanent.

```ts
// Before
const { value } = await controller.syncDataset("tasks", store.tasks);
store.tasks = value;

// After
await controller.syncDataset("tasks", {
  read: () => store.tasks,
  apply: async (merged) => {
    await db.withTransaction(async () => {
      store.tasks = merged;
    });
    return store.tasks;
  },
});
```

Kotlin mirrors the contract as `SharedDatasetMutator<T>`, with a
`sharedDatasetMutator(read, apply)` helper for lambda construction.

## Why

The previous signature bound the merge input at the call site, but the
controller serializes dataset operations, so the body could run seconds later.
Two syncs queued back to back both merged snapshots captured before the first
one's result existed. Moving the read inside the turn closes that window.

The return signature was also the wrong affordance. `syncDataset(id, value) →
merged` reads like a pure function, so every consumer assigned the result —
outside whatever lock guards local edits. Because the merged value is computed
before the network write completes, that assignment silently drops anything the
user changed in between. Applying it is a read-modify-write, and only the
consumer can make it atomic against its own store.

Callbacks alone were not enough: the snapshot controller already exposed
`readLocal` / `applyMerged`, and a consumer still shipped `applyMerged` as a
no-op. So `apply` returns a non-void value and the controller compares its
stable fingerprint against the merged value's, raising `state`
(`SyncKitErrorCode.STATE` on Android) on a mismatch. A no-op cannot typecheck,
and a partial apply fails loudly instead of diverging from the cloud.
Consumers with no local mirror may still return `merged` unchanged; sync-kit's
own control ledger does, because its state is derived entirely from the signed
remote events.

## Not changed

The snapshot controller's `sync("change")` coalescing is unchanged and was not
defective: `queuedChange` is cleared at the start of the queued turn, before
`readLocal` runs, so an edit that coalesces onto a queued sync is always
observed by it. The consumer-side ordering requirement — commit the edit before
calling `sync`, not after — is now documented rather than implied.

## Documentation

`docs/consumer-responsibilities.md` gains "The apply window", covering the
contract, the atomicity requirement, and the ordering rule for both the sharing
and snapshot paths.
