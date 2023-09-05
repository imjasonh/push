# `push`

This is an experimental Go backend and JavaScript frontend for sending push notifications to a browser.

This is mainly a learning exercise for me to learn how to do this.
Maybe someday I'll do something useful with it.

## Generate a keypair

To start, you'll need to generate a keypair, which will be used to sign the JWTs used to authenticate the push notifications.

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

## Running locally

### Run service

```
KO_DATA_PATH=kodata go run ./
```

Then load the URL in your browser: http://localhost:8080/
