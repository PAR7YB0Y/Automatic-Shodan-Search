<h1> Automatic Shodan Search </h1>
<p>Automate your shodan queries with this as<b>s</b> simple as possible python script!</p>



<h2><a id="general" class="anchor" aria-hidden="true" href="#installation"></a>General Info</h2>

<p>The script automates queries to shodan using its public API. All queries cover free shodan license. In a situation when there is a need to start general passive reconnaissance (get the most important things like hostnames, OS and especially open ports) for several network clusters, it may save a lot of time because you see where you should start your assessment maybe? It is worth to mention that "Last Update" column refers to the date when shodan cached information about specific IP. There's also parameter which allows save all results to csv.</p>

<img src="https://github.com/F3715H/AutomaticShodanSearch/blob/main/imgs/2.png" width=100% height=100%>

<p>The script currently works in several modes:<br>
<ul>
<li>query for a single IP address</li>
<li>query many different IP addresses</li>
<li>query single network cluster</li>
<li>query multiple network clusters</li>
</ul>
Optional switches:
<ul>
<li>verbosity - define wheter you want to display IP addresses which haven't been found in shodan.</li>
<li>output - save your results to CSV file </li>
<li>api - check information about API key. In practise used to verify connection establishment with the API</li>  
</ul>
</p>




<h2><a id="installation" class="anchor" aria-hidden="true" href="#installation"></a>Install & Config</h2>
<p>Install requirements:</p>
<pre><code>pip install requirements.txt</code></pre>
<p>Update line 258 with your shodan API key:</p>
<pre><code>api_key = "INSERT_YOUR_API_KEY_HERE" # CHANGE IT</code></pre>
<p>Then you may want to run the following command in order to verify whether connection with API establishes correctly:</p>
<pre><code>python ASS.py -a</code></pre>


<h2><a id="ExampleUsage" class="anchor" aria-hidden="true" href="#ExampleUsage"></a>Example usage</h2>
<img src="https://github.com/F3715H/AutomaticShodanSearch/blob/main/imgs/1.png" width=100% height=100%>

<p>Query specific IP addresses (separate by spaces):
<pre><code>python ASS.py -i 8.8.8.8 4.4.4.4</code></pre>


<p>Query single/multiple network clusters, display also "not found" IPs and save results to CSV file:
<pre><code>python ASS.py -n 192.168.1.0/24 172.16.0.0/16 -v -o data.csv</code></pre>

<h2><a id="updates" class="anchor" aria-hidden="true" href="#updates"></a>Future update goal</h2>
<p>Get txt file with ip addresses list as parameter</p>
