# Short web application token
The "SWA" token is similar to JWT token but it just shorter.

<img width="1083" alt="image" src="https://user-images.githubusercontent.com/41188285/164160359-cbdb789d-2f31-497e-95e6-83385a772c83.png">


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

const swat = createSWAT('Your-secret-key')
```

2. Issue new token

```ts
swat.create('1', 'user')
```

3. Verify a token

```ts
swat.verify(token)
```

4. Get token info

```ts
swat.parse(token)
```

5. Change to difference signature provider

```ts
// By default SWAT use HS256 to create signature
// Bellow is example to change HS512 algo
swat.use('HS512')
```

6. Custom signature provider

```ts
swat.use('YourAlgo', {
  sign: (data: string) => 'signature',
  verify: (data: string, signature: string) => true || false
})
```
