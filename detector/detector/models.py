from django.db import models

class ScanHistory(models.Model):
    url = models.URLField()
    result = models.CharField(max_length=100)
    features_triggered = models.TextField(null=True, blank=True)  # ✅ New field
    scanned_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.url} - {self.result}"
