## Mock oauth2server for mocking google chromium oauth server


### Clone the repo
```
git clone git@github.com:MasterK0927/oauthServer.git
```

### Install the modules
```
npm install
```

### Run the server (by default :3000)
```
nodemon server.js
```

### Tunnel it to https using ngrok
```
ngrok http http://localhost:3000
```

### Go to chromium\src\google_apis\gaia\gaia_urls.cc
```
Replace **kDefaultGaiaUrl** with the ngrok url
```