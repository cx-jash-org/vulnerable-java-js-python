// VULNERABLE: DOM-based XSS
function showSearchResults() {
    const params = new URLSearchParams(window.location.search);
    const searchTerm = params.get('q');

    // Direct innerHTML assignment - SAST will flag this
    document.getElementById('results').innerHTML =
        '<h2>Results for: ' + searchTerm + '</h2>';
}

// VULNERABLE: Open Redirect
function redirect() {
    const url = new URLSearchParams(window.location.search).get('target');
    window.location.href = url;
}

// VULNERABLE: eval with user input
function processFormula() {
    const userInput = document.getElementById('formula').value;
    const result = eval(userInput);
    return result;
}

document.addEventListener('DOMContentLoaded', showSearchResults);
