
const loginForm = document.getElementById("loginForm");
const message = document.getElementById("message");

loginForm.addEventListener("submit", async function(event) {

    event.preventDefault();

    const username = document.getElementById("username").value;
    const password = document.getElementById("password").value;

    message.textContent = "Checking your credentials...";

    try {

        const response = await fetch("/login", {
            method: "POST",

            headers: {
                "Content-Type": "application/json"
            },

            body: JSON.stringify({
                username: username,
                password: password
            })
        });

        const data = await response.json();

        if (response.ok) {

            // Store the session token for this browser session
            sessionStorage.setItem(
                "session_token",
                data.session_token
            );

            sessionStorage.setItem(
                "username",
                data.username
            );
            
          
            message.style.color = "#c6e57a";
            message.textContent = "Login successful!";
            setTimeout(function() {
               window.location.href = "/dashboard";
            }, 700);


        } else {

            message.style.color = "#8c3939";
            message.textContent = data.error || "Login failed.";

            if (data.remaining_attempts !== undefined) {
                message.textContent +=
                    " Remaining attempts: " + data.remaining_attempts;
            }
        }

    } catch (error) {

        message.style.color = "#8c3939";
        message.textContent =
            "Unable to connect to the server.";

        console.error(error);
    }

});
