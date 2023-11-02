import express from 'express'
import oidc from 'express-openid-connect'
import dotenv from 'dotenv'
import * as jose from 'jose'

dotenv.config()

const app = express()

app.use(oidc.auth({
	authorizationParams: {
		response_type: 'code', // This requires you to provide a client secret
		audience: process.env.AUTH0_AUDIENCE,
		scope: 'openid profile email create:orders update:users',
	},
	authRequired: false,
	auth0Logout: true,
	baseURL: 'http://localhost:3000',
	clientID: process.env.AUTH0_CLIENT_ID,
	clientSecret: process.env.AUTH0_CLIENT_SECRET,
	issuerBaseURL: `https://${process.env.AUTH0_DOMAIN}`,
	secret: 'LONG_RANDOM_STRING',
	
}));


// a custom middleware to check for scope/permissions
function requiresScope(requiredScope) {
  return (req, res, next) => {
    // Safely extract the access token
    const accessToken = req.oidc && req.oidc.accessToken ? req.oidc.accessToken.access_token : null;

    if (!accessToken || typeof accessToken !== 'string') {
      return res.status(403).send('Forbidden: no or invalid access token');
    }

    try {
      const decoded = jose.decodeJwt(accessToken);  // Decode without verification
      const scopes = decoded && decoded.scope ? decoded.scope.split(' ') : [];

      if (!scopes.includes(requiredScope)) {
        return res.status(403).send('Forbidden: insufficient scope');
      }

      next();
    } catch (e) {
      return res.status(403).send(`Forbidden: invalid token (${e.message})`);
    }
  };
}

app.get('/public', (req, res) => {
	res.send('this is a public route')
})

app.get('/protected', oidc.requiresAuth(), (req, res) => {
	res.send('this is a protected route')
})

app.get('/private', oidc.requiresAuth(), requiresScope('update:users'), (req, res) => {
	res.send('this is a private route')
});

// req.isAuthenticated is provided from the auth router
app.get('/', (req, res) => {
	res.send(req.oidc.isAuthenticated() ? 'Logged in' : 'Logged out')
});

const PORT = 3000
app.listen(PORT, () => {
	console.log('server listening')
})
