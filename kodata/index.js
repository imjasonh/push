document.body.onload = async function () {
    const response = await fetch("/pubkey");
    if (!response.ok) {
        console.error("fetching pubkey", response);
        return;
    }
    const publicKey = await response.text();
    console.log(`Public key '${publicKey}'`);

    const btn = document.createElement('button');
    btn.id = 'button';
    btn.textContent = "Loading...";
    document.body.appendChild(btn);
    console.log('Cookies:', document.cookie);
    if (document.cookie.indexOf('token=gho_') < 0) {
        console.log("No GH token found");
        btn.addEventListener('click', async () => { document.location = "/auth/start"; })
        btn.textContent = "Login with GitHub";
        return
    }

    navigator.serviceWorker.ready
        .catch((err) => { console.error("ready", err); })
        .then(async (serviceWorkerRegistration) => {
            console.log('ready', serviceWorkerRegistration);
            const subscription = await serviceWorkerRegistration.pushManager.getSubscription()
            console.log('subscription', subscription);
            if (subscription != null) {
                const current = btoa(String.fromCharCode.apply(null, new Uint8Array(subscription.options.applicationServerKey)))
                    .replace(/\//g, '_')
                    .replace(/\+/g, '-');
                if (current !== publicKey) {
                    console.log("Application server key is not the same",
                        `current='${current}'`,
                        `want='${publicKey}'`);
                    const successful = await subscription.unsubscribe();
                    console.log("unsubscribed", successful);
                } else {
                    console.log("Already subscribed with correct public key", current);
                    await register(subscription.endpoint);
                    btn.textContent = "Unsubscribe";
                    btn.onclick = async () => {
                        const successful = await subscription.unsubscribe();
                        console.log("unsubscribed", successful);
                        // Unregister from server
                        await unregister();
                        document.location.reload();
                    };
                    return
                }
            }

            btn.textContent = "Subscribe";
            btn.addEventListener('click', async () => {
                navigator.serviceWorker.register("worker.js")
                    .catch((err) => { console.error("registering", err); })
                    .then(async (serviceWorkerRegistration) => {
                        const subscription = await serviceWorkerRegistration.pushManager.subscribe({
                            userVisibleOnly: true,
                            applicationServerKey: publicKey.replace(/\=/g, ""),
                        })
                        await register(subscription.endpoint);
                        btn.textContent = "Unsubscribe";
                        btn.onclick = async () => {
                            const successful = await subscription.unsubscribe();
                            console.log("unsubscribed", successful);
                            // Unregister from server
                            await unregister();
                            document.location.reload();
                        };
                    })
            });
        });
};

this.onpush = (event) => {
    console.log('Push event data:', event.data);
    // This is handled by the service worker
};

async function register(endpoint) {
    console.log("Endpoint:", endpoint);
    const response = await fetch("/register", {
        method: "POST",
        body: JSON.stringify({ endpoint: endpoint }),
    });
    if (!response.ok) {
        console.error("registering", response);
        throw new Error(`Registration failed: ${response.status}`);
    }
    console.log("registered", response);
}

async function unregister() {
    console.log("Unregistering from server...");
    const response = await fetch("/unregister", {
        method: "POST",
    });
    if (!response.ok) {
        console.error("unregistering", response);
        throw new Error(`Unregistration failed: ${response.status}`);
    }
    console.log("unregistered", response);
}
