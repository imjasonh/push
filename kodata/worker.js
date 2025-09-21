addEventListener('push', function (event) {
    console.log('Push received', event);
    
    if (!event.data) {
        console.log('Push event but no data');
        return;
    }
    
    try {
        const data = event.data.json();
        console.log('Push data:', data);
        
        const promiseChain = self.registration.showNotification(
            data.title || 'GitHub Notification',
            {
                body: data.body || 'You have a new notification',
                icon: data.icon || '/icon.png',
                badge: data.badge || '/badge.png',
                data: data.data || {},
                requireInteraction: true,
                actions: [
                    {
                        action: 'view',
                        title: 'View'
                    },
                    {
                        action: 'dismiss',
                        title: 'Dismiss'
                    }
                ]
            }
        );
        
        event.waitUntil(promiseChain);
    } catch (error) {
        console.error('Error handling push event:', error);
    }
});

addEventListener('notificationclick', function (event) {
    console.log('Notification clicked:', event);
    event.notification.close();
    
    if (event.action === 'view' && event.notification.data && event.notification.data.url) {
        // Open the GitHub notification URL
        event.waitUntil(
            clients.openWindow(event.notification.data.url)
        );
    } else if (event.action !== 'dismiss') {
        // Default action - open the main app
        event.waitUntil(
            clients.openWindow('/')
        );
    }
});
