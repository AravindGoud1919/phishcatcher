from django.db import models

class ScanHistory(models.Model):
    url = models.URLField()
    result = models.CharField(max_length=50)
    scanned_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.url} - {self.result}"
