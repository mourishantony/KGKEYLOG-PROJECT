document.addEventListener("DOMContentLoaded", function () {
    let dbButton = document.getElementById("database-button");

    if (dbButton) {
        dbButton.addEventListener("click", function () {
            window.location.href = "/database";
        });
    }
});
