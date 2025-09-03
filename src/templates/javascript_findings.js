document.addEventListener('DOMContentLoaded', function() {
    // Existing filter and search functionality
    const filters = {
        severity: new Set(),
        scanner: new Set(),
        target: new Set()
    };

    const searchInput = document.getElementById('searchInput');
    const findingsGrid = document.getElementById('findings-grid');
    const findingCards = Array.from(findingsGrid.getElementsByClassName('finding-card'));

    // Pagination variables
    let currentPage = 1;
    const itemsPerPage = 20;
    let filteredCards = [...findingCards];

    // JSON Modal elements
    let jsonModal = null;
    
    initializeComponents();

    function initializeComponents() {
        createJsonModal();
        createPaginationControls();
        setupEventListeners();
        updateDisplay();
    }

    function createJsonModal() {
        // Create modal for JSON viewer
        jsonModal = document.createElement('div');
        jsonModal.className = 'json-modal';
        jsonModal.innerHTML = `
            <div class="json-modal-content">
                <div class="json-modal-header">
                    <h3>Finding Raw JSON Data</h3>
                    <button class="json-modal-close" aria-label="Close">&times;</button>
                </div>
                <div class="json-modal-body">
                    <pre class="json-content"></pre>
                </div>
                <div class="json-modal-footer">
                    <button class="btn btn-primary copy-json-btn">📋 Copy JSON</button>
                    <button class="btn btn-secondary json-modal-close">Close</button>
                </div>
            </div>
        `;
        document.body.appendChild(jsonModal);

        // Modal event listeners
        jsonModal.querySelectorAll('.json-modal-close').forEach(btn => {
            btn.addEventListener('click', () => closeJsonModal());
        });

        jsonModal.addEventListener('click', (e) => {
            if (e.target === jsonModal) closeJsonModal();
        });

        jsonModal.querySelector('.copy-json-btn').addEventListener('click', copyJsonToClipboard);
    }

    function createPaginationControls() {
        const paginationContainer = document.createElement('div');
        paginationContainer.className = 'pagination-container';
        paginationContainer.innerHTML = `
            <div class="pagination-info">
                <span class="results-count">Showing 0 of 0 findings</span>
            </div>
            <div class="pagination-controls">
                <button class="btn btn-sm prev-btn" disabled>← Previous</button>
                <span class="page-numbers"></span>
                <button class="btn btn-sm next-btn" disabled>Next →</button>
            </div>
        `;
        
        findingsGrid.parentNode.insertBefore(paginationContainer, findingsGrid);
        findingsGrid.parentNode.appendChild(paginationContainer.cloneNode(true));
    }

    function setupEventListeners() {
        // Filter buttons
        document.querySelectorAll('.btn-filter').forEach(button => {
            button.addEventListener('click', () => {
                const filterType = button.dataset.filterType;
                const filterValue = button.dataset.filterValue;

                button.classList.toggle('active');

                if (filters[filterType].has(filterValue)) {
                    filters[filterType].delete(filterValue);
                } else {
                    filters[filterType].add(filterValue);
                }

                applyFiltersAndUpdate();
            });
        });

        // Search input
        searchInput.addEventListener('input', debounce(applyFiltersAndUpdate, 300));

        // JSON view buttons
        document.addEventListener('click', (e) => {
            if (e.target.classList.contains('view-json-btn')) {
                const card = e.target.closest('.finding-card');
                showJsonModal(card);
            }
        });

        // Pagination controls
        document.addEventListener('click', (e) => {
            if (e.target.classList.contains('prev-btn')) {
                if (currentPage > 1) {
                    currentPage--;
                    updateDisplay();
                }
            } else if (e.target.classList.contains('next-btn')) {
                const maxPage = Math.ceil(filteredCards.length / itemsPerPage);
                if (currentPage < maxPage) {
                    currentPage++;
                    updateDisplay();
                }
            } else if (e.target.classList.contains('page-number')) {
                currentPage = parseInt(e.target.textContent);
                updateDisplay();
            }
        });

        // Keyboard shortcuts
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && jsonModal.style.display === 'flex') {
                closeJsonModal();
            }
        });
    }

    function applyFiltersAndUpdate() {
        applyFilters();
        currentPage = 1;
        updateDisplay();
    }

    function applyFilters() {
        const searchTerm = searchInput.value.toLowerCase();

        filteredCards = findingCards.filter(card => {
            const severity = card.dataset.severity;
            const scanner = card.dataset.scanner;
            const target = card.dataset.target;
            
            // Enhanced search - search in JSON data
            const jsonData = card.dataset.json || '';
            const cardText = card.textContent.toLowerCase();
            const combinedSearchText = cardText + ' ' + jsonData.toLowerCase();

            const severityMatch = filters.severity.size === 0 || filters.severity.has(severity);
            const scannerMatch = filters.scanner.size === 0 || filters.scanner.has(scanner);
            const targetMatch = filters.target.size === 0 || filters.target.has(target);
            const searchMatch = searchTerm === '' || combinedSearchText.includes(searchTerm);

            return severityMatch && scannerMatch && targetMatch && searchMatch;
        });
    }

    function updateDisplay() {
        // Hide all cards first
        findingCards.forEach(card => {
            card.style.display = 'none';
            card.classList.add('hidden');
        });

        // Calculate pagination
        const startIndex = (currentPage - 1) * itemsPerPage;
        const endIndex = startIndex + itemsPerPage;
        const pageCards = filteredCards.slice(startIndex, endIndex);

        // Show current page cards
        pageCards.forEach(card => {
            card.style.display = 'block';
            card.classList.remove('hidden');
        });

        updatePaginationControls();
    }

    function updatePaginationControls() {
        const totalResults = filteredCards.length;
        const maxPage = Math.ceil(totalResults / itemsPerPage);
        
        // Update results count
        document.querySelectorAll('.results-count').forEach(el => {
            const startItem = totalResults > 0 ? (currentPage - 1) * itemsPerPage + 1 : 0;
            const endItem = Math.min(currentPage * itemsPerPage, totalResults);
            el.textContent = `Showing ${startItem}-${endItem} of ${totalResults} findings`;
        });

        // Update pagination buttons
        document.querySelectorAll('.prev-btn').forEach(btn => {
            btn.disabled = currentPage <= 1;
        });

        document.querySelectorAll('.next-btn').forEach(btn => {
            btn.disabled = currentPage >= maxPage;
        });

        // Update page numbers
        document.querySelectorAll('.page-numbers').forEach(container => {
            container.innerHTML = generatePageNumbers(currentPage, maxPage);
        });
    }

    function generatePageNumbers(current, max) {
        let pages = [];
        
        if (max <= 7) {
            for (let i = 1; i <= max; i++) {
                pages.push(i);
            }
        } else {
            if (current <= 4) {
                pages = [1, 2, 3, 4, 5, '...', max];
            } else if (current >= max - 3) {
                pages = [1, '...', max - 4, max - 3, max - 2, max - 1, max];
            } else {
                pages = [1, '...', current - 1, current, current + 1, '...', max];
            }
        }

        return pages.map(page => {
            if (page === '...') {
                return '<span class="page-ellipsis">...</span>';
            } else {
                const isActive = page === current ? ' active' : '';
                return `<button class="btn btn-sm page-number${isActive}">${page}</button>`;
            }
        }).join('');
    }

    function showJsonModal(card) {
        const jsonData = card.dataset.json;
        if (!jsonData) return;

        try {
            const parsedJson = JSON.parse(decodeURIComponent(jsonData));
            const formattedJson = JSON.stringify(parsedJson, null, 2);
            
            jsonModal.querySelector('.json-content').textContent = formattedJson;
            jsonModal.style.display = 'flex';
            document.body.style.overflow = 'hidden';
        } catch (e) {
            console.error('Error parsing JSON:', e);
            jsonModal.querySelector('.json-content').textContent = jsonData;
            jsonModal.style.display = 'flex';
            document.body.style.overflow = 'hidden';
        }
    }

    function closeJsonModal() {
        jsonModal.style.display = 'none';
        document.body.style.overflow = '';
    }

    function copyJsonToClipboard() {
        const jsonContent = jsonModal.querySelector('.json-content').textContent;
        navigator.clipboard.writeText(jsonContent).then(() => {
            const btn = jsonModal.querySelector('.copy-json-btn');
            const originalText = btn.textContent;
            btn.textContent = '✅ Copied!';
            setTimeout(() => {
                btn.textContent = originalText;
            }, 2000);
        });
    }

    function debounce(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    }
});