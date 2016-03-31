---
title: insert title here
author: Shrayes Ramesh
date: March 26, 2016
---

# Cybersecurity without context: an unscalable paradigm

The organizations <> partners with are tasked with protecting networks that are huge, evolving, diverse, and whose adversaries who are constantly experimenting with new attack vectors. As a natural consequence, those organizations face a serious Big Data problem, as their network logs arrive in huge volume, velocity, variety, and veracity.

To handle the scope of their network defense problem, most organizations apply the following cybersecurity paradigm:
*  First, the ecosystem contains a myriad of automated rules-based tools that flag on individual, granular logs. These alerts most commonly take the form of "single IP or host was recorded conducting malicious activity x, for which an instrument was generated or rule was in place to detect malicious activity x."
* If an organization typically records a billion raw network logs per day, the number of rules that are fired off might still number in the thousands. Therefore the organization utilizes a tiered operations staff who each sift through hundreds of ticketed alerts per day to validate and take action on issues. This process is labor-intensive.
* Finally, a feedback loop is implemented where the ruleset is adjusted, by adding new alert types as new threats are discovered, and by refitting and often turning off rules-based tools that fail to provide value.

While the current cybersecurity paradigm is straightforward to implement, it is ultimately limited by its ability to scale. The strain on this paradigm arrives in the form of a __lack of context__ to advise both automated tools and human operators.  Automated alerting on singular __granular logs__ frequently misses activities in the context of other related neighboring logs, as in the following examples:
* A heuristic rule that flags traffic sizes over a particular amount will miss exfiltration events that occur on weekends or holidays when the context of a network involves less traffic.
* As another example, multiple IPs, each individually flagged for a denial of service, might be operating in concert and should be flagged as a distributed denial of service with other potential collaborators investigated.
* As another example, a single successful VPN login to a server may be insignificant, but scripted periodic VPN logins over time might raise more suspicion and warrant investigation.
* As a fourth example, malicious actors may randomize and distribute active reconnaissance to avoid suspicion, but once the activity is isolated and aggregated, their danger becomes more obvious.

The above examples are just a small sample of the types of issues raised by conducting cybersecurity without context.  This lack of situational awareness leads to rules being insufficient and ultimately ignored or disabled, greatly limiting the effectiveness of the current cybersecurity paradigm.  Even though these large organizations have a Big Data problem, the current paradigm does not effectively leverage big data analytics.  The race to develop new ad-hoc rules for an evolving network might be misguided when faced with a necessity to pause and slowly take a meaningful 100-ft view.

While organizations are struggling to keep up with an unscalable cybersecurity paradigm, advances in distributed technologies capable of storing and processing the massive amounts of data allow for the implementation of a new approach that optimally __leverages__ distributed analytics to provide context for network defense rather than fights against it.

This white paper describes several important lessons learned when conducting network defense at scale, applying new algorithmic approaches to identify context in networks.


# From granular logs to granular units of activity

## Speeding up human workflows

Network activity is typically instrumented to arrive as **streams of granular logs**.
*  For example, generic network activity is recorded in granular netflow logs, where each terminated session records metadata about the source and destination IPs, the protocol and ports used, the duration and amount of traffic (bytes, packets) that was transmitted in that session, along with an associated timestamp.
*  As another example, web activity is recorded in granular web logs, where each request records metadata about the client, the client's browser, the server, resources on the server, the result of the http request, along with an associated timestamp.
*  Similarly, generic host-based activity might be recorded in granular host-level logs, recording metadata on important events like logins, configuration changes, and file manipulations, along with an associated timestamp

The most frequent question a human operators asks when faced with an alert about singular logs is _"what else?"_-- what else has this actor done on the network, what else has happened on this resource, who else is doing similar things in a similar way, and how common is this activity? The manual labor involved in answering the "what else" questions account for a large unnecessary component of the time analysts spend resolving tickets.  One bad log is difficult to classify on its own; however, a group of logs which are suspicious together is a clearer, actionable insight.

Analysis limited to single instances of granular logs fail to leverage context that is available in the data, as in the examples listed above.  The first paradigm shift proposed in this paper is a shift away from granular logs to reasoning about **granular units of activity**. Actors on the internet, whether malicious or benign, are fundamentally humans who have made decisions about which actions to take **together** (whether they are realized through a manual series of actions or through pre-coded automated scripts). Individual network logs need to be grouped together to generate understanding of the true underlying decision-making process of human actors. Network analysts must first fully record and consider the set of individual actions that comprise this "unit of activity."

## Sessionized units of activity

This section describes several approaches to building up an appropriate "unit of activity" for each type of network activity.

**FIGURE XX** displays some examples of how to segment large volumes of granular singular logs into (also large) volumes of granular units of activity.

* For netflow, communications between two IPs might occur across multiple ports and protocols. All of the logs between two IPs (a _dyad_) before a particular timeout (30 minutes, for example) is likely to be driven by the same process and can be collected together as a granular unit of activity.
* Alternatively, also for netflow, a single IP might interact with multiple IPs in one continuous period of activity. All of an IP's logs before a particular timeout of activity can be collected together as a granular unit of activity.
* For web logs or other similar device logs, a client or user session might be represented as a clickstream, consisting of all of the urls or domains accessed before a timeout or logout.

The segmentation of flows into sessions as described above imply that optimal "units of activity" should be time-dependent.  There are two motivations for breaking up an actor's activity over time into multiple chunks.  First, time-dependency allows tracking of IPs, hosts, or clients _over time_ to build a history of an actor's pattern-of-life. Second, as some addresses and domains on networks are dynamically allocated and therefore frequently change, incorrectly aggregating dynamic activity over time generates aggregations are are noisy and ultimately less useful.

There are two approaches to chunk together raw logs across time.  The first simple approach is **time-binning**, as demonstrated in the following SQL query. For a given actor (a client, IP, username, etc), each raw log row is annotated by binning its timestamp into predetermined intervals. Bins might arbitrarily range in resolution from 5 minutes, to hourly, to daily.

    ##time-binning
    select
    uid,
    *,
    floor(timestamp / seconds) as timebin
    from rawlogs;

There are several drawbacks to the time-binning approach to constructing units of activity. First, processes that are low, slow, yet long-running will be broken apart, rendering the context for long-running activity incomplete. Second, fixed bins allow offensive adversaries to more easily engineer scripts to generate noise along the boundaries of fixed cut-points generated by fixed time bins. Finally, the arbitrary choice of the length of each time interval might mix together activity that should have been grouped together at tighter frequencies. In other words, arbitrary bins create arbitrary noise.

In contrast to fixed-bin time-binning, **sessioniziation** offers an alternative approach that theoretically generates less arbitrary noise.  Sessionization takes all of the data for the actor, sorts the data by time, and then annotates each raw log row with a session identifier that groups together **all activity before a period of inactivity**. For exposition, sessionization can be expressed using the following two sql queries that utilize windowing and partition functions.

    ##window functions to sessionize

    ##part 1: record the start of new sessions
    ##delta: 1(inactivity > seconds)
    create table tmp as
    select
    uid,
    feature,
    if(timestamp - lag(timestamp)
      over (partition by uid, order by timestamp, feature)
      > seconds, 1, 0) as delta
    from rawtable;

    ##part 2: cumulative sum to generate sessionid
    select
    sum(a.delta)
      over (partition by uid, order by timestamp, feature
            rows between unbounded preceedinga and current row)
    as sessionid,
    *
    from tmp;


Sessionization, while slightly more computationally intensive, remedies some of the undesirable properties of time-binning. By identifying blocks of continuous activity of different lengths, sessionization more accurately identifies the context for both rapid bursts of activity as well as long, persistent processes.

## Feature generation

As granular units of activity are aggregations of the raw granular flows, a rich set of quantifiable features can explain each single unit of activity and place it in the context of other units of activity present in the global network.  Once a time-dependent granular unit of activity is chosen, there are typically at least two different mathematical ways of representing the behavior contained in that activity. Those two types involve **categorical features** that explain what happened in a session, as well as **continuous features** that explain how much raw log activity is being aggregated.

**FIGURE XX** illustrates how one can construct meaningful behavioral profiles by aggregating flows.

* For netflow sessions, there are a set of *continuous* features describing the total amount of traffic (bytes, packets, optionally in both directions) and the duration of traffic (both in terms of the start and ending timestamps as well as the sum of the duration of individual flows), and a separate set of *categorical* features corresponding to the number of times a session involved particular ports or protocols (in both directions).
* Also for netflow, if a unit of activity contains multiple IPs, the set of categorical features includes the list of other IPs in the session and how many times those IPs were present during the session.
* For web logs or other similar device or event logs, the set of categorical features involve counts of the number of times each resources, domains, event types or message types were accessed.

The process of moving from granular logs to granular units of activity cuts Big Data into pieces that are more easily digested by human experts. Each chunk of activity innately contains the necessary context needed to make actionable insights. Nonetheless, this process ultimately does not solve the Big Data problem. **present something about 1b flows to 100m sessions or some way of explaining how much aggregation is going on**. To meaningfully address this Big Data problem, the first task of a successful paradigm will involve tools to conduct meaningful exploratory data analysis.

# Exploratory situational awareness

Internet traffic is large and diverse. Diverse organizations contain a menagerie of departments and verticals each with their own business policies, and in some cases their own security policies. Many organizations have assets open to the internet, either in the form of internet portals for employees and often internet portals for business partners and customers. Not only are network security issues different between organizations in the same industry, but they are different across industries as well. From the offensive standpoint, the activities and methodologies of attackers vary as well across geography, motives, and sophistication levels and are constantly evolving.

All of this human-driven diversity in network use sits on top of the way the internet itself is technically structured to be an open, heterogeneous ecosystem of different protocols and policies. When compared to other Big Data domains involving financial transactions or health records, the internet is an order of magnitude more complex in terms of the nuance of what generates the logs that make it into the SIEM.

* therefore, exploratory analysis is still important
* insert stuff here about end-user tools that display aggregate distributions. importance of histograms over simple statistics like mean and median
* can find clusters without actually running clustering algorithms
* lead into unsupervised automation

# Clustering big datasets: unsupervised automation

## Identifying typical behaviors and patterns-of-life: algorithms considered

* hierarchical O(N^2) clustering
  * **OPTICS**
* fixed or low k models (learned with either bayesian sampling or with an EM algorithm)
  * **spherical k-means**, random projection k-means, unsupervised naive bayes (learned with an EM algorithm)
  * **unsupervised niche clustering** and other genetic variants (learned with a genetic algorithm)
  * **LDA**, **dirichlet unigram mixture** (bayesian sampling)
* **ensemble clustering**
  * bootstraps and model aggregation


* density estimation with **random projection histograms** (ensemble of empirical density estimates)
* balanced, ordered clusters with **CDF Annealing**


## From clusters to context

A clustering algorithm applied to cyber data takes as an input granular units of activity, typically represented by vectors of feature counts specific to the type of network log. The output of clustering algorithms include *cluster labels*, *measures of anomaly*, and *visualization coordinates*. This section describes the nature of these three clustering outputs, their usefulness to network operations and network defense, and prioritizes clustering algorithms by their ability to produce consistently useful actionable insights.

### Cluster labels

Clustering algorithms typically output **cluster labels** for each input unit. Labels can be used to partition and group activities into set of clusters.  Conceptually, breaking apart large networks into meaningful components is crucial for identifying context. For example, unsupervised algorithms applied to web logs might automatically learn to distinguish activity generated by IT staff relative to HR staff, or external partners relative to internal employees, etc.  Similar approaches applied to netflow logs might find different classes of activity (like DNS or web or LDAP) each with its own signature. Once clustering is complete, human operators might be able to observe new granular units of activity and quickly learn to match up the activity with the type of behavior that generated it.

For all clustering algorithms the number of clusters is chosen by a human operator, either explicitly (as in k-means, LDA, etc.), or implicitly through setting parameters (as in OPTICS, UNC, etc.). Since unsupervised cluster labels are not meaningful by themselves the algorithms typically have a process to output an explanation for each cluster of activity in terms of the characteristic features that provide context about it. Because of this need for a human explanation,  the number of clusters chosen by human operators tends to remain manageable. **EVIDENCE NEEDED: Even algorithmically, Typical chinese-restaurant-process or perplexity experiments find the optimal number or clusters starts plateauing around 20 clusters.**.

Under the right circumstances, all of the clustering algorithms considered can successfully learn to split apart activity into _a few_ big groups of activity. From the standpoint of empirical validation of unsupervised machine learning algorithms, these clustering algorithms are quite successful.  The clusters are distinct, compact, and tend to map nicely to an easily interpretable human explanation. Nonetheless, given that internet traffic is fundamentally large and diverse, none of the clustering algorithms above have the resolution capable of understanding the nuances of most organizations' networks.

As data sizes grow and new instruments to collect traffic data are implemented, most of the growth in the quantity of data comes from _new_ types of activity being recorded rather than more of the _same_ type of activity. In contrast, the number of output clusters typically does not grow fast enough to keep pace. Trying to classify thousands to millions of different types of activities into "just a few types" is fundamentally flawed.

The primary lesson about clustering algorithms is that by themselves, cluster labels are not very useful, especially when the number of output clusters is small (small enough for a human to want to feasible try to explain each and every cluster). In contrast, **ordered clustering for visualization** tends to be more useful to human operators. For example, the OPTICS algorithm produces an ordering of data points, stretched out on a line. For each granular input unit of activity, given a "scale" or "resolution" parameter from a human, OPTICS is able to provide context and find points that should be clumped together with that input point.

At different resolution levels, hierarchical clustering algorithms like OPTICS provide the best ability to capture the necessary nuance present in big quantities of diverse data. Unfortunately, almost all
 hierarchical clustering algorithms are O(N^2) and are impossible to scale. To address these concerns, I developed a prototype of an ordered, balanced, clustering algorithm called "CDF annealing."

### Measures of anomaly

Clustering algorithms also typically output **measures of anomaly** for each input unit. Depending on the algorithm, the interpretation of this anomaly score differs. There are three categories of measures of anomaly, each measuring slightly different notions of outlier behavior:

* Some algorithms are capable of reporting a measurement that corresponds closely to density or distance to a set of nearest neighbors. These measures of anomaly report _how many other bits of activity are close enough to me_ (the input unit of activity).
* Clustering algorithms can also produce a measure of closeness to other points in the cluster. These measures of anomaly report _how different am I from the typical pattern of activity for my cluster?_.
* Finally, their are entropy and log-likelihood scores that report the certainty or consistency of an input point's final cluster assignment. These measures of anomaly report _how easy is it to put this unit of activity in a single cluster?_

In contrast to the the first category of anomaly measures (density estimates), which are nonparametric and more model-agnostic, the second and third category of anomaly measures rely on an underlying clustering model or clustering algorithm that encorporate several significant modeling assumptions. 

Because of the limitations in attempting to group numerous types of network activity into "just a few types."

* Too much nuance in actual network behavior.
* leads to larger false positive rate (and larger number of positives)

* do not need an expensive algorithm to compute density estimates in high dimensions.
* RPHmap at scale


## Finding malicious activity

* mapping M data points to M outlier scores: outlier scores are still big data
* user-defined filtering.
* multi-method cross validation

* aggregate outlier scores and changes in behavior
* importance of correctly picking unit of analysis
