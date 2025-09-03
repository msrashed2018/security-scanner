document.addEventListener('DOMContentLoaded', function() {
    const severityFilters = document.querySelectorAll('.severity-filter');
    const searchInput = document.getElementById('searchInput');
    const findingCards = document.querySelectorAll('.finding-card');

    function filterFindings() {
        const activeSeverities = new Set();
        severityFilters.forEach(btn => {
            if (btn.classList.contains('active')) {
                activeSeverities.add(btn.dataset.severity);
            }
        });

        const searchTerm = searchInput.value.toLowerCase();

        findingCards.forEach(card => {
            const cardSeverity = card.dataset.severity;
            const cardText = card.textContent.toLowerCase();

            const severityMatch = activeSeverities.size === 0 || activeSeverities.has(cardSeverity);
            const searchMatch = cardText.includes(searchTerm);

            if (severityMatch && searchMatch) {
                card.classList.remove('hidden');
            } else {
                card.classList.add('hidden');
            }
        });
    }

    severityFilters.forEach(button => {
        button.addEventListener('click', function() {
            this.classList.toggle('active');
            filterFindings();
        });
    });

    searchInput.addEventListener('input', filterFindings);
});