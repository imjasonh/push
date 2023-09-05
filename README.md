# `push`

This is an experimental Go backend and JavaScript frontend for sending push notifications to a browser.

This is mainly a learning exercise for me to learn how to do this.
Maybe someday I'll do something useful with it.

## Setup

To bootstrap, create empty files named `gh-client-id` and `gh-secret`. We'll fill these in later.

### Generate a keypair

You'll also need to generate a keypair, which will be used to sign the JWTs used to authenticate the push notifications.

```
go run ./ keygen
```

## Deploying to Cloud Run

```
gcloud auth login
gcloud auth application-default login
terraform init
terraform apply -auto-approve
```

This will print a URL to the deployed service, for example:

```
url = "https://push-blahblah-blah.a.run.app"
```

This packages up the Go backend using `ko_build`, and runs the service with secret access to the private key you generated before.

### Get a GitHub client ID and secret

Create a new GitHub OAuth app here: https://github.com/settings/developers

Update the empty files named `gh-client-id` and `gh-secret` that you created before, with the client ID and secret, respectively.

For the redirect URL, use the URL printed by Terraform, with `/auth/callback` appended to it, for example:

```
https://push-blahblah-blah.a.run.app/auth/callback
```

## Running locally

```
./local.sh
```

Then load the URL in your browser: http://localhost:8080/

TODO: GH OAuth doesn't work locally yet.
