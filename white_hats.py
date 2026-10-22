"""Optional durable capability/outbox instrument. See WHITE_HATS.md for trust boundary."""
import json
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass

MAX_INT = 2**63 - 1


def positive(value):
    if type(value) is not int or not 0 < value <= MAX_INT:
        raise ValueError('expected positive integer minor units')
    return value


def text(value):
    if type(value) is not str or not value or len(value) > 256:
        raise ValueError('expected nonempty identifier of at most 256 characters')
    return value


@dataclass(frozen=True)
class Transfer:
    task: str
    account: str
    recipient: str
    currency: str
    amount: int

    def encoded(self):
        for value in (self.task, self.account, self.recipient, self.currency):
            text(value)
        positive(self.amount)
        return json.dumps(self.__dict__, sort_keys=True, separators=(',', ':'))


class Store:
    """Trusted host API; never expose root/delegate/revoke or the DB to model tools.

    Identity and task arguments must originate in authenticated host context.
    Each method uses a separate SQLite connection, including across processes.
    """
    def __init__(self, path, clock=time.time):
        self.path, self.clock = str(path), clock
        if self.path == ':memory:':
            raise ValueError('a persistent database path is required')
        with self.transaction() as db:
            db.executescript('''
                CREATE TABLE IF NOT EXISTS grants(
                  id TEXT PRIMARY KEY, parent TEXT REFERENCES grants(id),
                  principal TEXT NOT NULL, actor TEXT NOT NULL, task TEXT NOT NULL,
                  account TEXT NOT NULL, recipient TEXT NOT NULL, currency TEXT NOT NULL,
                  budget INTEGER NOT NULL, spent INTEGER NOT NULL DEFAULT 0,
                  expires INTEGER NOT NULL, revoked INTEGER NOT NULL DEFAULT 0);
                CREATE TABLE IF NOT EXISTS outbox(
                  nonce TEXT PRIMARY KEY, grant_id TEXT NOT NULL REFERENCES grants(id),
                  payload TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'pending');
            ''')

    @contextmanager
    def transaction(self):
        db = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        db.row_factory = sqlite3.Row
        try:
            db.execute('PRAGMA foreign_keys=ON')
            db.execute('PRAGMA synchronous=FULL')
            db.execute('BEGIN IMMEDIATE')
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def chain(self, db, grant_id):
        result = []
        while grant_id is not None:
            if len(result) >= 32:
                raise PermissionError('delegation depth exceeded')
            row = db.execute('SELECT * FROM grants WHERE id=?', (grant_id,)).fetchone()
            if row is None or row['revoked'] or self.clock() >= row['expires']:
                raise PermissionError('inactive grant')
            result.append(row)
            grant_id = row['parent']
        return result

    def root(self, grant_id, principal, actor, transfer, budget, expires):
        """Trusted issuer only: attest prior principal approval; this does not solicit it."""
        for value in (grant_id, principal, actor):
            text(value)
        transfer.encoded()
        positive(budget)
        positive(expires)
        if budget < transfer.amount or expires <= self.clock():
            raise ValueError('invalid root limits')
        with self.transaction() as db:
            db.execute('INSERT INTO grants(id,principal,actor,task,account,recipient,currency,budget,expires) VALUES(?,?,?,?,?,?,?,?,?)',
                       (grant_id, principal, actor, transfer.task, transfer.account,
                        transfer.recipient, transfer.currency, budget, expires))

    def delegate(self, parent_id, child_id, *, actor, child_actor, budget, expires):
        for value in (parent_id, child_id, actor, child_actor):
            text(value)
        positive(budget)
        positive(expires)
        with self.transaction() as db:
            chain = self.chain(db, parent_id)
            parent = chain[0]
            if (len(chain) >= 32 or actor != parent['actor'] or
                    expires <= self.clock() or expires > parent['expires'] or
                    budget > parent['budget'] - parent['spent']):
                raise PermissionError('delegation does not narrow authority')
            db.execute('INSERT INTO grants(id,parent,principal,actor,task,account,recipient,currency,budget,expires) VALUES(?,?,?,?,?,?,?,?,?,?)',
                       (child_id, parent_id, parent['principal'], child_actor,
                        parent['task'], parent['account'], parent['recipient'],
                        parent['currency'], budget, expires))

    def prepare(self, grant_id, nonce, transfer, *, principal, actor, task):
        """Atomically spend shared ancestor budgets and enqueue immutable intent."""
        text(nonce)
        # Capture one immutable serialized value; dispatch reads only this snapshot.
        payload = transfer.encoded()
        snapshot = json.loads(payload)
        with self.transaction() as db:
            chain = self.chain(db, grant_id)
            leaf = chain[0]
            if (principal != leaf['principal'] or actor != leaf['actor'] or
                    task != leaf['task'] or any(snapshot[k] != leaf[k] for k in
                    ('task', 'account', 'recipient', 'currency'))):
                raise PermissionError('transaction context mismatch')
            amount = snapshot['amount']
            if any(amount > row['budget'] - row['spent'] for row in chain):
                raise PermissionError('sequence budget exceeded')
            # Unique nonce insertion fails before any budget change; rollback is atomic.
            db.execute('INSERT INTO outbox(nonce,grant_id,payload) VALUES(?,?,?)',
                       (nonce, grant_id, payload))
            for row in chain:
                db.execute('UPDATE grants SET spent=spent+? WHERE id=?', (amount, row['id']))
        return nonce

    def revoke(self, grant_id, *, principal):
        """Trusted authenticated principal operation; descendants inherit revocation."""
        with self.transaction() as db:
            row = db.execute('SELECT principal FROM grants WHERE id=?', (grant_id,)).fetchone()
            if row is None or row['principal'] != principal:
                raise PermissionError('principal mismatch')
            db.execute('UPDATE grants SET revoked=1 WHERE id=?', (grant_id,))

    def dispatch(self, nonce, send):
        """Call trusted adapter with stored payload and stable provider idempotency key.

        send must enforce provider idempotency and raise on uncertain/failure outcomes.
        Concurrent retries can call send more than once with identical key/payload.
        """
        with self.transaction() as db:
            row = db.execute('SELECT * FROM outbox WHERE nonce=?', (nonce,)).fetchone()
            if row is None:
                raise KeyError(nonce)
            if row['state'] == 'sent':
                return False
            payload = row['payload']
        send(idempotency_key=nonce, payload=payload)
        with self.transaction() as db:
            db.execute("UPDATE outbox SET state='sent' WHERE nonce=?", (nonce,))
        return True
