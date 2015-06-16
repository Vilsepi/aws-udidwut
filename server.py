#!/usr/bin/env python

import boto.exception
import boto.cloudtrail
import logging
import json
import zlib

import settings
import secrets

logging.basicConfig(format='%(asctime)s %(levelname)-8s %(message)s')
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)


class TrailBucket:

    cloudtrail = None
    s3 = None
    bucket = None
    bucket_name = ""
    cloudtrail_list = None
    s3_key_prefix = ""
    log_store = {}

    def __init__(self, aws_region="eu-west-1", **kwargs):

        self.cloudtrail = boto.cloudtrail.connect_to_region(aws_region, **kwargs)

        try:
            trails = self.cloudtrail.describe_trails()['trailList']
            self.bucket_name = trails[0]['S3BucketName']
            self.s3_key_prefix = trails[0]['S3KeyPrefix']
        except:
            log.error("Failed to find a cloudtrail")

        try:
            self.s3 = boto.connect_s3(**kwargs)
            self.bucket = self.s3.get_bucket(self.bucket_name)
        except:
            log.error("Could not find the cloudtrail bucket")
        self.refresh_cloudtrail_file_list()

    def refresh_cloudtrail_file_list(self):
        """ Get the latest file list from S3. Costs little money and takes a few seconds. """
        self.cloudtrail_list = self.bucket.list()
        log.info("Cloudtrail currently has {0} files".format(sum(1 for _ in self.cloudtrail_list)))
        return

    def download_logs(self, limit=10):
        """ Downloads gzipped json log files from S3 if they have not been downloaded yet. """

        if self.cloudtrail_list:
            for item in self.cloudtrail_list:
                if item.key not in self.log_store:
                    if limit > 0:
                        try:
                            raw_data_gz = item.get_contents_as_string()
                            raw_data = zlib.decompress(raw_data_gz, 16 + zlib.MAX_WBITS)
                            json_data = json.loads(raw_data)
                            self.log_store[item.key] = json_data
                        except:
                            log.warning("Failed to dump cloudtrail log file. (Directories cause this for now)")
                        limit -= 1
                    else:
                        break

    def print_logs(self):
        for key, log_file in self.log_store.iteritems():
            #print json.dumps(log_file, indent=4)

            for record in log_file['Records']:
                print "{0}\t{1}\t{2}\t{3}\t{4}\t{5}".format(record['eventTime'],
                                                            record['eventName'],
                                                            record.get('userIdentity').get('arn'),
                                                            record.get('eventSource'),
                                                            record.get('userAgent'),
                                                            record.get('sourceIPAddress'))


if __name__ == "__main__":

    trail_bucket = TrailBucket(aws_region=settings.aws_region,
                               aws_access_key_id=secrets.aws_access_key_id,
                               aws_secret_access_key=secrets.aws_secret_access_key)

    trail_bucket.download_logs(limit=100)
    trail_bucket.print_logs()
