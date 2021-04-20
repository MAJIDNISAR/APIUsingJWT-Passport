# How To Implement API Authentication with JSON Web Tokens and Passport



- By Majid Nisar 

### Introduction

Many web applications and APIs use a form of authentication to protect resources and restrict their access only to verified users.

JSON Web Token (JWT) is an open standard that defines a compact and self-contained way for securely transmitting information between parties as a JSON object.

This guide will walk you through how to implement authentication for an API using JWTs and [Passport](http://www.passportjs.org/), an authentication middleware for [Node](http://nodejs.org/).

Here a brief overview of the application you will be building:

- The user signs up, and a user account is created.
- The user logs in, and a JSON web token is assigned to the user.
- This token is sent by the user when trying to access certain secure routes.
- Once the token has been verified, the user is then allowed to access the route.

## Prerequisites

To complete this tutorial, you will need:

- Node.js installed locally, which you can do by following [How to Install Node.js and Create a Local Development Environment](https://www.digitalocean.com/community/tutorial_series/how-to-install-node-js-and-create-a-local-development-environment).
- [MongoDB](https://www.mongodb.com/) installed and running locally, which you can do by following [the official documentation](https://docs.mongodb.com/manual/installation/).
- Downloading and installing a tool like [Postman](https://www.getpostman.com/) will be required for testing API endpoints.

This tutorial was verified with Node v14.2.0, `npm` v6.14.5, and `mongodb-community` v4.2.6.

## Step 1 — Setting up the Project

Let’s start by setting up the project. In your terminal window, create a directory for the project:

```bash
mkdir jwt-and-passport-auth
```

 

Copy

And navigate to that new directory:

```bash
cd jwt-and-passport-auth
```

 

Copy

Next, initialize a new `package.json`:

```bash
npm init -y
```

 

Copy

Install the project dependencies:

```bash
npm install --save bcrypt@4.0.1 body-parser@1.19.0 express@4.17.1 jsonwebtoken@8.5.1 mongoose@5.9.15 passport@0.4.1 passport-jwt@4.0.0 passport-local@1.0.0
```

 

Copy

You will need `bcrypt` for hashing user passwords, `jsonwebtoken` for signing tokens, `passport-local` for implementing local strategy, and `passport-jwt` for retrieving and verifying JWTs.

**Warning**: When running install, you may encounter issues with `bcrypt` depending on the version of Node you are running.Refer to the [README](https://github.com/kelektiv/node.bcrypt.js#version-compatibility) to determine compatibility with your environment.

At this point, your project has been initialized and all the dependencies have been installed. Next, you will be adding a database to store user information.

## Step 2 — Setting up the Database

A [database schema](https://en.wikipedia.org/wiki/Database_schema) establishes the types of data and structure of the database. Your database will require a schema for users.

Create a `model` directory:

```bash
mkdir model
```

 

Copy

Create a `model.js` file in this new directory:

```bash
nano model/model.js
```

 

Copy

The `mongoose` library is used to define a schema that is mapped to a MongoDB collection. In the schema, an email and password will be required for a user. The `mongoose` library takes the schema and converts it into a model:

model/model.js

```js
const mongoose = require('mongoose');

const Schema = mongoose.Schema;

const UserSchema = new Schema({
  email: {
    type: String,
    required: true,
    unique: true
  },
  password: {
    type: String,
    required: true
  }
});

const UserModel = mongoose.model('user', UserSchema);

module.exports = UserModel;
```

 

Copy

You should avoid storing passwords in plain text because if an attacker manages to get access to the database, the passwords can be read.

To avoid this, you will use a package called `bcrypt` to hash user passwords and store them safely. Add the library and the following lines of code:

model/model.js

```js
// ...

const bcrypt = require('bcrypt');

// ...

const UserSchema = new Schema({
  // ...
});

UserSchema.pre(
  'save',
  async function(next) {
    const user = this;
    const hash = await bcrypt.hash(this.password, 10);

    this.password = hash;
    next();
  }
);

// ...

module.exports = UserModel;
```

 

Copy

The code in the `UserScheme.pre()` function is called a pre-hook. Before the user information is saved in the database, this function will be called, you will get the plain text password, hash it, and store it.

`this` refers to the current document about to be saved.

`await bcrypt.hash(this.password, 10)` passes the password and the value of *salt round* (or *cost*) to `10`. A higher cost will run the hashing for more iterations and be more secure. It has a trade-off of being more computationally intensive to the point that it may impact your application’s performance.

Next, you replace the plain text password with the hash and then store it.

Finally, you indicate you are done and should move on to the next middleware with `next()`.

You will also need to make sure that the user trying to log in has the correct credentials. Add the following new method:

model/model.js

```js
// ...

const UserSchema = new Schema({
  // ...
});

UserSchema.pre(
  // ...
});

UserSchema.methods.isValidPassword = async function(password) {
  const user = this;
  const compare = await bcrypt.compare(password, user.password);

  return compare;
}

// ...

module.exports = UserModel;
```

 

Copy

`bcrypt` hashes the password sent by the user for login and checks if the hashed password stored in the database matches the one sent. It will return `true` if there is a match. Otherwise, it will return `false` if there is not a match.

At this point, you have a schema and model defined for your MongoDB collection.

## Step 3 — Setting up Registration and Login Middleware

Passport is an authentication middleware used to authenticate requests.

It allows developers to use different strategies for authenticating users, such as using a local database or connecting to social networks through APIs.

In this step, you’ll be using the local (email and password) strategy.

You will use the `passport-local` strategy to create middleware that will handle user registration and login. This will then be plugged into certain routes and be used for authentication.

Create an `auth` directory:

```bash
mkdir auth
```

 

Copy

Create an `index.js` file in this new directory:

```bash
nano auth/index.js
```

 

Copy

Start by requiring `passport`, `passport-local`, and the `UserModel` that was created in the previous step:

auth/index.js

```js
const passport = require('passport');
const localStrategy = require('passport-local').Strategy;
const UserModel = require('../model/model');
```

 

Copy

First, add a Passport middleware to handle user registration:

auth/index.js

```js
// ...

passport.use(
  'signup',
  new localStrategy(
    {
      usernameField: 'email',
      passwordField: 'password'
    },
    async (email, password, done) => {
      try {
        const user = await UserModel.create({ email, password });

        return done(null, user);
      } catch (error) {
        done(error);
      }
    }
  )
);
```

 

Copy

This code saves the information provided by the user to the database, and then sends the user information to the next middleware if successful.

Otherwise, it reports an error.

Next, add a Passport middleware to handle user login:

auth/index.js

```js
// ...

passport.use(
  'login',
  new localStrategy(
    {
      usernameField: 'email',
      passwordField: 'password'
    },
    async (email, password, done) => {
      try {
        const user = await UserModel.findOne({ email });

        if (!user) {
          return done(null, false, { message: 'User not found' });
        }

        const validate = await user.isValidPassword(password);

        if (!validate) {
          return done(null, false, { message: 'Wrong Password' });
        }

        return done(null, user, { message: 'Logged in Successfully' });
      } catch (error) {
        return done(error);
      }
    }
  )
);
```

 

Copy

This code finds one user associated with the email provided.

- If the user does not match any users in the database, it returns a `"User not found"` error.
- If the password does not match the password associated with the user in the database, it returns a `"Wrong Password"` error.
- If the user and password match, it returns a `"Logged in Successfully"` message, and the user information is sent to the next middleware.

Otherwise, it reports an error.

At this point, you have a middleware for handling signing up and logging in.

## Step 4 — Creating the Signup Endpoint

[Express](https://expressjs.com/) is a web framework that provides routing. In this step, you will create a route for a `signup` endpoint.

Create a `routes` directory:

```bash
mkdir routes
```

 

Copy

Create a `index.js` file in this new directory:

```bash
nano routes/index.js
```

 

Copy

Start by requiring `express` and `passport`:

routes/index.js

```js
const express = require('express');
const passport = require('passport');

const router = express.Router();

module.exports = router;
```

 

Copy

Next, add handling of a POST request for `signup`:

routes/index.js

```js
// ...

const router = express.Router();

router.post(
  '/signup',
  passport.authenticate('signup', { session: false }),
  async (req, res, next) => {
    res.json({
      message: 'Signup successful',
      user: req.user
    });
  }
);

module.exports = router;
```

 

Copy

When the user sends a POST request to this route, Passport authenticates the user based on the middleware created previously.

You now have a `signup` endpoint. Next, you will need a `login` endpoint.

## Step 5 — Creating the Login Endpoint and Signing the JWT

When the user logs in, the user information is passed to your custom callback, which in turn creates a secure token with the information.

In this step, you will create a route for a `login` endpoint.

First, require `jsonwebtoken`:

routes/routes.js

```js
const express = require('express');
const passport = require('passport');
const jwt = require('jsonwebtoken');

// ...
```

 

Copy

Next, add handling of a POST request for `login`:

routes/routes.js

```js
// ...

const router = express.Router();

// ...

router.post(
  '/login',
  async (req, res, next) => {
    passport.authenticate(
      'login',
      async (err, user, info) => {
        try {
          if (err || !user) {
            const error = new Error('An error occurred.');

            return next(error);
          }

          req.login(
            user,
            { session: false },
            async (error) => {
              if (error) return next(error);

              const body = { _id: user._id, email: user.email };
              const token = jwt.sign({ user: body }, 'TOP_SECRET');

              return res.json({ token });
            }
          );
        } catch (error) {
          return next(error);
        }
      }
    )(req, res, next);
  }
);

module.exports = router;
```

 

Copy

You should not store sensitive information such as the user’s password in the token.

You store the `id` and `email` in the payload of the JWT. You then sign the token with a secret or key (`TOP_SECRET`). Finally, you send back the token to the user.

**Note:** You set `{ session: false }` because you do not want to store the user details in a session. You expect the user to send the token on each request to the secure routes.This is especially useful for APIs, but it is not a recommended approach for web applications for performance reasons.

You now have a `login` endpoint. A successfully logged in user will generate a token. However, your application does not do anything with the token yet.

## Step 6 — Verifying the JWT

So now you’ve handled user signup and login, the next step is allowing users with tokens access to certain secure routes.

In this step, you will verify that the tokens haven’t been manipulated and are valid.

Revisit the `auth.js` file:

```bash
nano auth/index.js
```

 

Copy

Add the following lines of code:

auth/index.js

```js
// ...

const JWTstrategy = require('passport-jwt').Strategy;
const ExtractJWT = require('passport-jwt').ExtractJwt;

passport.use(
  new JWTstrategy(
    {
      secretOrKey: 'TOP_SECRET',
      jwtFromRequest: ExtractJWT.fromUrlQueryParameter('secret_token')
    },
    async (token, done) => {
      try {
        return done(null, token.user);
      } catch (error) {
        done(error);
      }
    }
  )
);
```

 

Copy

This code uses `passport-jwt` to extract the JWT from the query parameter. It then verifies that this token has been signed with the secret or key set during logging in (`TOP_SECRET`). If the token is valid, the user details are passed to the next middleware.

**Note:** If you will need extra or sensitive details about the user that are not available in the token, you could use the `_id` available on the token to retrieve them from the database.

Your application is now capable of both signing tokens and verifying them.

## Step 7 — Creating Secure Routes

Now, let’s create some secure routes that only users with verified tokens can access.

Create a new `secure-routes.js` file:

```bash
nano routes/secure-routes.js
```

 

Copy

Next, add the following lines of code:

routes/secure-routes.js

```js
const express = require('express');
const router = express.Router();

router.get(
  '/profile',
  (req, res, next) => {
    res.json({
      message: 'You made it to the secure route',
      user: req.user,
      token: req.query.secret_token
    })
  }
);

module.exports = router;
```

 

Copy

This code handles a GET request for `profile`. It returns a `"You made it to the secure route"` message. It also returns information about the `user` and `token`.

The goal will be so that only users with a verified token will be presented with this response.

## Step 8 — Putting it all Together

So now that you’re all done with creating the routes and authentication middleware, you can put everything together.

Create a new `app.js` file:

```bash
nano app.js
```

 

Copy

Next, add the following code:

app.js

```js
const express = require('express');
const mongoose = require('mongoose');
const passport = require('passport');
const bodyParser = require('body-parser');

const UserModel = require('./model/model');

mongoose.connect('mongodb://127.0.0.1:27017/passport-jwt', { useMongoClient: true });
mongoose.connection.on('error', error => console.log(error) );
mongoose.Promise = global.Promise;

require('./auth');

const routes = require('./routes/');
const secureRoute = require('./routes/secure-routes');

const app = express();

app.use(bodyParser.urlencoded({ extended: false }));

app.use('/', routes);

// Plug in the JWT strategy as a middleware so only verified users can access this route.
app.use('/user', passport.authenticate('jwt', { session: false }), secureRoute);

// Handle errors.
app.use(function(err, req, res, next) {
  res.status(err.status || 500);
  res.json({ error: err });
});

app.listen(3000, () => {
  console.log('Server started.')
});
```

 

Copy

**Note:** Depending on your version of `mongoose`, you may encounter the following message: `WARNING: The 'useMongoClient' option is no longer necessary in mongoose 5.x, please remove it.`.You may also encounter deprecation notices for `useNewUrlParser`, `useUnifiedTopology`, and `ensureIndex` (`createIndexes`).During troubleshooting, we were able to resolve these by modifying the `mongoose.connect` method call and adding a `mongoose.set` method call:`mongoose.connect("mongodb://127.0.0.1:27017/passport-jwt", {  useNewUrlParser: true,  useUnifiedTopology: true, }); mongoose.set("useCreateIndex", true);` Copy

Run your application with the following command:

```bash
node app.js
```

 

Copy

You will see a `"Server started."` message. Leave the application running to test it.

## Step 9 — Testing with Postman

Now that you’ve put everything together, you can use Postman to test your API authentication.

**Note:** If you need assistance navigating the Postman interface for requests, consult [the official documentation](https://learning.postman.com/docs/postman/sending-api-requests/requests/).

First, you will have to register a new user in your application with an email and password.

In Postman, set up the request to the `signup` endpoint you created in `routes.js`:

```
POST localhost:3000/signup
Body
x-www-form-urlencoded
```

And send over these details through the `Body` of your request:

| Key      | Value                 |
| -------- | --------------------- |
| email    | `example@example.com` |
| password | `password`            |

When that’s done, click the **Send** button to initiate the `POST` request:

```json
Output{
    "message": "Signup successful",
    "user": {
        "_id": "[a long string of characters representing a unique id]",
        "email": "example@example.com",
        "password": "[a long string of characters representing an encrypted password]",
        "__v": 0
    }
}
```

 

Copy

Your password displays as an encrypted string because this is how it is stored in the database. This is a result of the pre-hook you wrote in `model.js` to use `bcrypt` to hash the password.

Now, log in with the credentials and get your token.

In Postman, set up the request to the `login` endpoint you created in `routes.js`:

```
POST localhost:3000/login
Body
x-www-form-urlencoded
```

And send over these details through the `Body` of your request:

| Key      | Value                 |
| -------- | --------------------- |
| email    | `example@example.com` |
| password | `password`            |

When that’s done, click the **Send** button to initiate the `POST` request:

```json
Output{
    "token": "[a long string of characters representing a token]"
}
```

 

Copy

Now that you have your token, you will send over this token whenever you want to access a secure route. Copy and paste it for later use.

You can test how your application handles verifying tokens by accessing `/user/profile`.

In Postman, set up the request to the `profile` endpoint you created in `secure-routes.js`:

```
GET localhost:3000/user/profile
Params
```

And pass your token in a query parameter called `secret_token`:

| Key          | Value                                                |
| ------------ | ---------------------------------------------------- |
| secret_token | `[a long string of characters representing a token]` |

When that’s done, click the **Send** button to initiate the `GET` request:

```json
Output{
    "message": "You made it to the secure route",
    "user": {
        "_id": "[a long string of characters representing a unique id]",
        "email": "example@example.com"
    },
    "token": "[a long string of characters representing a token]"
}
```

 

Copy

The token will be collected and verified. If the token is valid, you’ll be given access to the secure route. This is a result of the response you created in `secure-routes.js`.

You can also try accessing this route, but with an invalid token, the request will return an `Unauthorized` error.

## Conclusion

In this tutorial, you set up API authentication with JWT and tested it with Postman.

JSON web tokens provide a secure way of creating authentication for APIs. An extra layer of security can be added by encrypting all the information within the token, thereby making it even more secure.

