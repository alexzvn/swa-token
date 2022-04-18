# Short web application token
The "SWA" token is similar to JWT token but it just shorter.

Bellow is the schema of SWA token:
```txt
type:id:issue_at:expires|signature
```
The `type` and `id` can be anything in string and `issue_at`, `expires` is timestamp. The `expires` field could be empty so the token will be valid forever. The `signature` create by hmac`sha256` and convert to base64 string.


## Install

```bash
# npm users
npm i swa-token

# yarn users
yarn add swa-token
```
## How to use

1. Create SWAT instance

```ts
import SWAT from 'swa-token'

const secret = 'Your secret key'
const algo = 'sha256' // optional

const swat = new SWAT(secret, algo)
```

2. Issue new token

```ts
const type = 'user'
const id = '1'
const expires = Date.now() + 1000 // optional

const token = swat.create(type, id, expires)
```

3. Verify a token

```ts
swat.verify(token)
```

4. Get token info

```ts
swat.infoOf(token)
```
