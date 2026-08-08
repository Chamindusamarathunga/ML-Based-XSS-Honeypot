// JavaScript for Honeypot System - Client Side

// Handle search form submission and display results (Reflected XSS)
document.addEventListener('DOMContentLoaded', function () {
    // Load existing comments on page load
    loadComments();
});

// Display search results (VULNERABLE - Reflected XSS)
function displaySearchResults(query) {
    const resultsDiv = document.getElementById('searchResults');

    // INTENTIONALLY VULNERABLE: Directly inserting user input without sanitization
    // This allows reflected XSS attacks for honeypot purposes
    resultsDiv.innerHTML = `
        <h3>Search Results for: ${query}</h3>
        <p>You searched for: ${query}</p>
        <p class="alert alert-info">Showing results matching "${query}"</p>
    `;

    // Log the search attempt to backend
    logSearchAttempt(query);
}

// Log search attempt to Flask backend
function logSearchAttempt(query) {
    fetch('/api/log-search', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            query: query,
            timestamp: new Date().toISOString(),
            user_agent: navigator.userAgent,
            page_url: window.location.href
        })
    })
        .catch(error => {
            console.error('Error logging search:', error);
        });
}

// Handle comment form submission
const commentForm = document.getElementById('commentForm');
if (commentForm) {
    commentForm.addEventListener('submit', function (e) {
        e.preventDefault();

        const formData = {
            name: document.getElementById('commentName').value,
            email: document.getElementById('commentEmail').value,
            comment: document.getElementById('commentText').value,
            timestamp: new Date().toISOString(),
            user_agent: navigator.userAgent
        };

        // Submit comment to backend
        fetch('/api/add-comment', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(formData)
        })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    // Clear form
                    commentForm.reset();

                    // Show success message
                    showSuccessMessage('Comment posted successfully!');

                    // Reload comments
                    loadComments();
                }
            })
            .catch(error => {
                console.error('Error submitting comment:', error);
            });
    });
}

// Load and display comments (VULNERABLE - Stored XSS)
function loadComments() {
    fetch('/api/get-comments')
        .then(response => response.json())
        .then(data => {
            displayComments(data.comments);
        })
        .catch(error => {
            console.error('Error loading comments:', error);
        });
}

// Display comments (INTENTIONALLY VULNERABLE - Stored XSS)
function displayComments(comments) {
    const commentsList = document.getElementById('commentsList');

    if (!comments || comments.length === 0) {
        commentsList.innerHTML = '<p class="no-comments">No comments yet. Be the first to comment!</p>';
        return;
    }

    // INTENTIONALLY VULNERABLE: Directly inserting user-generated content without sanitization
    // This allows stored XSS attacks for honeypot purposes
    let commentsHTML = '';
    comments.forEach(comment => {
        commentsHTML += `
            <div class="comment-item">
                <div class="comment-header">
                    <span class="comment-author">${comment.name}</span>
                    <span class="comment-date">${formatDate(comment.timestamp)}</span>
                </div>
                <div class="comment-content">
                    ${comment.comment}
                </div>
            </div>
        `;
    });

    commentsList.innerHTML = commentsHTML;
}

// Format date for display
function formatDate(timestamp) {
    const date = new Date(timestamp);
    return date.toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'long',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    });
}

// Show success message
function showSuccessMessage(message) {
    const formContainer = document.querySelector('.comment-form-container');
    const alertDiv = document.createElement('div');
    alertDiv.className = 'alert alert-success';
    alertDiv.textContent = message;

    formContainer.insertBefore(alertDiv, formContainer.firstChild);

    // Remove message after 3 seconds
    setTimeout(() => {
        alertDiv.remove();
    }, 3000);
}
