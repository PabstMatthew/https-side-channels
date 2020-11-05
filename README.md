# HTTPS Side Channels
This is an ongoing project to infer the browsing of a client by 
eavesdropping on their network traffic.

## Approach
The high-level flow of analysis so far is to match TLS packets in a capture 
to specific domains. Then, the timestamps of requests are used to cluster 
requests for a particular domain. Next, the clusters of requests within domains 
are correlated to form a profile for a specific request.

