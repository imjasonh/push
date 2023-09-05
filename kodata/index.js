
document.body.onload = async function () {
    const response = await fetch("/pubkey");
    if (!response.ok) {
        console.error("fetching pubkey", response);
        return;
    }
    const publicKey = await response.text();
    console.log(`Public key '${publicKey}'`);

    const serviceWorkerRegistration = await navigator.serviceWorker.ready;
    const subscription = await serviceWorkerRegistration.pushManager.getSubscription()
    if (subscription == null) {
        console.log("Subscription is null");
        return;
    }
    const current = btoa(String.fromCharCode.apply(null, new Uint8Array(subscription.options.applicationServerKey)))
        .replace(/\//g, '_')
        .replace(/\+/g, '-');
    if (current !== publicKey) {
        console.log("Application server key is not the same",
            `current='${current}'`,
            `want='${publicKey}'`);
        await subscription.unsubscribe();
        console.log("unsubscribed", successful);
    } else {
        console.log("Already subscribed with correct public key", current);
        console.log("Endpoint:", subscription.endpoint);
    }

    document.getElementById('button').addEventListener('click', async () => {
        const serviceWorkerRegistration = await navigator.serviceWorker.register("worker.js")
        const pushSubscription = await serviceWorkerRegistration.pushManager.subscribe({
            userVisibleOnly: true,
            applicationServerKey: publicKey,
        })
        console.log("Endpoint:", pushSubscription.endpoint);
        const response = await fetch("/register", {
            method: "POST",
            body: JSON.stringify({
                endpoint: pushSubscription.endpoint,
            }),
        })
        if (!response.ok) {
            console.error("registering", response);
        } else {
            console.log("registered!");
        }
    });
};

this.onpush = (event) => {
    console.log(event.data); // TODO
};

