from django.db import models

class Staff(models.Model):
    name = models.CharField(max_length=100)
    rfid = models.CharField(max_length=50, unique=True)  # RFID tag

    def __str__(self):
        return self.name

class Key(models.Model):
    lab_name = models.CharField(max_length=100)
    rfid = models.CharField(max_length=50, unique=True)   # RFID field to store RFID data

    def __str__(self):
        return f"{self.lab_name}"

from django.db import models

class History(models.Model):
    staff_rfid = models.CharField(max_length=255)
    key_rfid = models.CharField(max_length=255)
    action_time = models.DateTimeField(auto_now_add=True)  # Timestamp for when the action occurred

    @property
    def staff_name(self):
        """Fetch the staff name based on the RFID."""
        staff = Staff.objects.filter(rfid=self.staff_rfid).first()
        return staff.name if staff else "Unknown Staff"

    @property
    def lab_name(self):
        """Fetch the lab name based on the RFID."""
        key = Key.objects.filter(rfid=self.key_rfid).first()
        return key.lab_name if key else "Unknown Lab"

    def __str__(self):
        return f"{self.staff_name} - {self.lab_name} at {self.action_time}"


class Temporary(models.Model):
    staff_rfid = models.CharField(max_length=255, unique=True)  # Ensures no duplicate entries
    key_rfid = models.CharField(max_length=255)

    @property
    def staff_name(self):
        """Fetch the staff name based on the RFID."""
        staff = Staff.objects.filter(rfid=self.staff_rfid).first()
        return staff.name if staff else "Unknown Staff"

    @property
    def lab_name(self):
        """Fetch the lab name based on the RFID."""
        key = Key.objects.filter(rfid=self.key_rfid).first()
        return key.lab_name if key else "Unknown Lab"

    def __str__(self):
        return f"{self.staff_name} - {self.lab_name}"