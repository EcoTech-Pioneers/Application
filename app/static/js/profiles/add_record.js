document.getElementById('record-form').addEventListener('submit', function (e) {
                e.preventDefault();

                fetch('/api/v1/add_record', {
                    method: 'POST',
                    body: new FormData(this),
                })
                .then(response => response.json())
                .then(data => {
                    showAlert(data.message);

                    if (data.message === 'Record added successfully') {
                        window.location.href = '/profiles/all_records';
                    }
                })
                .catch(error => {
                    console.error(error);
                    // Display an error alert
                    showAlert('Adding record failed', 'error');
                });
});

            function showAlert(message, type = 'success') {
                const alertElement = document.getElementById('alertMessage');
                alertElement.innerText = message;
                alertElement.className = `alert ${type} p-3 mb-6`;
                alertElement.style.display = 'block';

                setTimeout(() => {
                    alertElement.style.display = 'none';
                }, 5000);
            }
