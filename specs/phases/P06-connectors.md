# P06: Production Connectors

Status: Baseline v0.1

### P06-PHO-001: Reconcile PhotoKit at startup
- Type: Event-driven
- Statement: When the PhotoKit connector starts, the system shall reconcile the configured scope because change notifications are not a durable synchronization cursor.
- Verification: Native connector test with missed changes.

### P06-PHO-002: Treat missing access as unavailable
- Type: Unwanted
- Statement: If a PhotoKit asset disappears because of permission, scope, or iCloud availability changes, the connector shall mark the source unavailable without deleting canonical wardrobe state.
- Verification: Permission and availability transition tests.

### P06-GML-001: Synchronize Gmail incrementally
- Type: Event-driven
- Statement: When Gmail authorization is active, the connector shall perform an initial bounded message reconciliation and then process mailbox history from a persisted cursor.
- Verification: Gmail sandbox integration test.

### P06-GML-002: Recover expired Gmail history
- Type: Unwanted
- Statement: If Gmail rejects an expired history cursor, the connector shall perform a full reconciliation and shall deduplicate source records by provider identity and revision.
- Verification: Simulated Gmail history expiration.

### P06-AUT-001: Store credentials in Keychain
- Type: Event-driven
- Statement: When a production connector receives an OAuth refresh token, the connector shall store it in Keychain and keep access tokens memory-only.
- Verification: Connector secret-storage test.

### P06-AUT-002: Revoke disconnected connectors
- Type: Event-driven
- Statement: When the user disconnects a connector, the system shall attempt provider revocation, remove local durable credentials, and preserve imported evidence until separately deleted.
- Verification: Disconnect and residual-secret test.

### P06-GPH-001: Treat Google Photos selection as import
- Type: Optional
- Statement: Where Google Photos Picker is enabled, the connector shall materialize selected media before temporary URLs expire and shall treat the result as an immutable import batch rather than continuous synchronization.
- Verification: Picker contract test with expired URL handling.
