    function fetchEventData() {
        return fetch('/api/v1/events')
            .then(response => {
                if (!response.ok) {
                    throw new Error('Network response was not ok');
                }
                return response.json();
            });
    }

    // Function to create an event card HTML element
    function createEventCard(event) {
        return `
           <div class="bg-white rounded-lg shadow-md">
            <img src="${event.imageUrl}" alt="${event.title}" class="w-full h-40 object-cover rounded-t-lg">
            <div class="p-4">
                <h2 class="text-xl font-semibold mb-2">${event.title}</h2>
                <p class="text-sm text-gray-600 mb-2">Organizer: ${event.organizer}</p>
                <p class="text-sm text-gray-600 mb-2">Venue: ${event.venue}</p>
                <p class="text-sm text-gray-600 mb-2">
                    <strong>Date:</strong> ${moment(event.startDateTime).format('MMMM D, YYYY')}
                </p>
                <p class="text-sm text-gray-600 mb-2">
                    <strong>Time:</strong> ${moment(event.startDateTime).format('h:mm A')} - ${moment(event.endDateTime).format('h:mm A')}
                </p>
                <p class="text-sm text-gray-600">${event.description}</p>
            </div>
            <div class="p-4 bg-gray-100 rounded-b-lg">
                <button class="bg-blue-500 text-white py-2 px-4 rounded hover:bg-blue-600">Book Event</button>
            </div>
        </div>
        `;
    }

    // Fetch event data and create event cards when the page loads
    document.addEventListener('DOMContentLoaded', function() {
        const eventContainer = document.getElementById('event-container');
        fetchEventData()
            .then(data => {
                data.items.forEach(event => {
                    eventContainer.innerHTML += createEventCard(event);
                });
            })
            .catch(error => {
                console.error('Error fetching event data:', error);
            });
    });
