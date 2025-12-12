from django.db import models

class NetworkConnection(models.Model):
    duration = models.IntegerField()

    protocol_type = models.CharField(
        max_length=10,
        choices=[
            ('tcp', 'tcp'),
            ('udp', 'udp'),
            ('icmp', 'icmp'),
        ]
    )

    service = models.CharField(max_length=50)

    src_bytes = models.IntegerField()
    dst_bytes = models.IntegerField()

    flag = models.CharField(
        max_length=10,
        choices=[
            ('SF', 'SF'), ('S0', 'S0'), ('REJ', 'REJ'), ('RSTR', 'RSTR'),
            ('RSTO', 'RSTO'), ('SH', 'SH'), ('S1', 'S1'), ('S2', 'S2'),
            ('S3', 'S3'), ('OTH', 'OTH'), ('RSTOS0', 'RSTOS0'),
        ]
    )

    wrong_fragment = models.IntegerField()
    urgent = models.IntegerField()

    count = models.IntegerField()
    serror_rate = models.FloatField(null=True, blank=True)
    rerror_rate = models.FloatField(null=True, blank=True)
    same_srv_rate = models.FloatField(null=True, blank=True)
    diff_srv_rate = models.FloatField(null=True, blank=True)

    srv_count = models.IntegerField()
    srv_serror_rate = models.FloatField(null=True, blank=True)
    srv_rerror_rate = models.FloatField(null=True, blank=True)
    srv_diff_host_rate = models.FloatField(null=True, blank=True)

    dst_host_count = models.IntegerField()
    dst_host_srv_count = models.IntegerField()
    dst_host_same_srv_rate = models.FloatField(null=True, blank=True)
    dst_host_diff_srv_rate = models.FloatField(null=True, blank=True)
    dst_host_same_src_port_rate = models.FloatField(null=True, blank=True)
    dst_host_srv_diff_host_rate = models.FloatField(null=True, blank=True)
    dst_host_serror_rate = models.FloatField(null=True, blank=True)
    dst_host_srv_serror_rate = models.FloatField(null=True, blank=True)
    dst_host_rerror_rate = models.FloatField(null=True, blank=True)
    dst_host_srv_rerror_rate = models.FloatField(null=True, blank=True)

    def __str__(self):
        return f"{self.protocol_type} - {self.service} - {self.duration}s"
