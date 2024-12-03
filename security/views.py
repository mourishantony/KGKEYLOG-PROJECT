from datetime import datetime
from django.shortcuts import render , redirect
from django.contrib.auth import authenticate, login
from django.contrib import messages
from .models import Staff, Key ,History,Temporary
from django.db.models import Max



def login_view(request):
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return redirect('register')  # Redirect to the register page after successful login
        else:
            messages.error(request, "Invalid username or password.")

    return render(request, "login.html")

from django.shortcuts import render
from .models import Staff, Key, History, Temporary

def register_key(request):
    if request.method == "POST":
        staff_rfid = request.POST.get("rfid")
        key_rfid = request.POST.get("key_rfid")

        # Fetch associated staff and key objects
        staff = Staff.objects.filter(rfid=staff_rfid).first()
        key = Key.objects.filter(rfid=key_rfid).first()

        if not staff or not key:
            return render(request, "register.html", {
                "key_interaction": "Invalid Staff or Key RFID. Please try again.",
            })

        # Save entry to History
        History.objects.create(staff_rfid=staff_rfid, key_rfid=key_rfid)

        # Check if the entry exists in Temporary
        existing_entry = Temporary.objects.filter(staff_rfid=staff_rfid, key_rfid=key_rfid).first()

        if existing_entry:
            # If it exists, remove it (Key Returned)
            existing_entry.delete()
            key_interaction = f"Key '{key.lab_name}' returned by {staff.name}."
            
            # Update key status in Key model
            key.status = "Returned"
            key.save()
        else:
            # If it does not exist, add it (Key Taken)
            Temporary.objects.create(
                staff_rfid=staff_rfid,
                key_rfid=key_rfid,
                  # Add lab_name to Temporary
            )
            key_interaction = f"Key '{key.lab_name}' taken by {staff.name}."

            # Update key status in Key model
            key.status = "Taken"
            key.save()

        # Render the result
        return render(request, "register.html", {
            "key_interaction": key_interaction,
            "staff": staff,
        })

    return render(request, "register.html")
