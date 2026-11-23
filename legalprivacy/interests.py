"""Interest personas: coherent, harmless themes for the noise (optional).

Idea from NoisyCompany and phantom-noise. Uniform randomness is easy to filter out:
a real person has a handful of steady interests. With personas on, a few themes are
active at a time (3 by default), chosen from the ones you allow, and they change every
so often (10 days by default). A share of visits and searches then follows them.

The draw is seeded from a random value saved in your settings, so it stays stable for
the period on this computer but differs from everyone else's.
"""
from __future__ import annotations

import hashlib
import random
import time

# Mainstream, safe sites and everyday searches per theme.
CATEGORIES: dict[str, dict] = {
    "Data science": {"sites": {"aclanthology.org": 2, "airflow.apache.org": 2, "ai.google": 5, "aijobs.net": 1,
                               "archive.ics.uci.edu": 2, "arxiv.org": 12, "aws.amazon.com/sagemaker/": 5, "chromadb.com": 2,
                               "cloud.google.com/bigquery": 5, "colab.research.google.com": 12, "commoncrawl.org": 1,
                               "cs229.stanford.edu": 2, "d3js.org": 5, "data.gov": 5, "data.worldbank.org": 5, "data.un.org": 2,
                               "datalemur.com": 2, "datasetsearch.research.google.com": 2, "dbt.com": 2, "deepmind.google": 5,
                               "distill.pub": 1, "dvc.org": 2, "duckdb.org": 5, "fast.ai": 2, "feast.dev": 1, "flourish.studio": 2,
                               "flowingdata.com": 2, "greatexpectations.io": 2, "huggingface.co": 12, "huggingface.co/spaces": 5,
                               "icml.cc": 2, "jmlr.org": 2, "jupyter.org": 5, "kafka.apache.org": 5, "labelstud.io": 2,
                               "leetcode.com": 12, "lightgbm.readthedocs.io": 2, "matplotlib.org": 5, "mathworld.wolfram.com": 5,
                               "mlflow.org": 2, "ocw.mit.edu": 5, "onnx.ai": 2, "openreview.net": 5, "optuna.org": 2,
                               "otexts.com/fpp3/": 2, "paperswithcode.com": 1, "plotly.com": 5, "pola.rs": 2, "posit.co": 5,
                               "powerbi.microsoft.com": 5, "pytorch.org": 12, "scikit-learn.org": 5, "scipy.org": 5,
                               "seaborn.pydata.org": 5, "spark.apache.org": 5, "sqlbolt.com": 2, "statquest.org": 2,
                               "stats.stackexchange.com": 5, "streamlit.io": 5, "tensorflow.org": 12, "towardsdatascience.com": 5,
                               "wandb.ai": 5, "www.analyticsvidhya.com": 5, "www.comet.com": 2, "www.coursera.org": 12,
                               "www.datacamp.com": 5, "www.dataquest.io": 2, "www.datasciencecentral.com": 2,
                               "www.deeplearning.ai": 5, "www.edx.org": 12, "www.evidentlyai.com": 2, "www.freecodecamp.org": 12,
                               "www.geeksforgeeks.org": 12, "www.getdbt.com": 2, "www.github.com": 12, "www.google.com": 12,
                               "www.gradio.app": 5, "www.hackerrank.com": 12, "www.itl.nist.gov/div898/handbook/": 2,
                               "www.kaggle.com": 12, "www.kdnuggets.com": 5, "www.langchain.com": 5, "www.llamaindex.ai": 2,
                               "www.machinelearningmastery.com": 5, "www.microsoft.com/microsoft-fabric": 5,
                               "www.nature.com/natmachintell/": 2, "www.numpy.org": 5, "www.openintro.org": 2, "www.openml.org": 2,
                               "www.openai.com": 12, "www.ourworldindata.org": 5, "www.pandas.pydata.org": 5, "www.python.org": 12,
                               "www.r-bloggers.com": 5, "www.r-project.org": 5, "www.ray.io": 2, "www.realpython.com": 5,
                               "www.reddit.com/r/datascience/": 5, "www.reddit.com/r/MachineLearning/": 5, "www.roboflow.com": 5,
                               "www.semanticscholar.org": 5, "www.snowflake.com": 5, "www.stackoverflow.com": 12,
                               "www.statlearning.com": 2, "www.statology.org": 5, "www.stratascratch.com": 2, "www.tableau.com": 5,
                               "www.tensorflow.org": 12, "www.thegradient.pub": 2, "www.trychroma.com": 2, "www.wolfram.com": 5,
                               "www.xgboost.ai": 2, "zenodo.org": 5, "pypi.org": 5, "docs.python.org": 5, "cran.r-project.org": 2,
                               "statsmodels.org": 2},
                     "queries": ["{t}", "{t} example", "how to {t}", "{t} python", "{t} explained", "{t} pandas",
                                 "{t} stack overflow", "{t} vs", "best way to {t}"],
                     "topics": ["pandas groupby", "random forest hyperparameters", "train test split", "cross validation",
                                "logistic regression", "xgboost vs lightgbm", "pca explained", "confusion matrix",
                                "roc auc", "time series forecasting", "fine tune transformers", "sql window functions",
                                "numpy broadcasting", "matplotlib subplots", "bayesian inference", "causal inference",
                                "feature engineering", "k-means clustering", "gradient descent", "jupyter shortcuts",
                                "polars vs pandas", "data leakage", "shap values", "imbalanced classes",
                                "duckdb parquet", "scikit-learn pipeline", "pytorch dataloader", "embedding similarity"]},
    "Objectivism": {"sites": {"aynrand.org": 6, "atlassociety.org": 6, "aynrandcenter.org": 3, "newideal.aynrand.org": 4,
                               "courses.aynrand.org": 2, "learn.aynrand.org": 2, "aru.aynrand.org": 1, "theobjectivestandard.com": 5,
                               "forum.objectivismonline.com": 4, "www.objectivistliving.com": 2, "www.galtsgulchonline.com": 2,
                               "aynrandlexicon.com": 3, "objectivistmedia.com": 2, "intellectualactivist.com": 2,
                               "objectivismindepth.com": 2, "objectivist.blog": 1, "objectivestandard.org": 1, "thinkingdirections.com": 1,
                               "capitalism.org": 1, "www.aynrandsociety.org": 1, "anthemfoundation.org": 1, "anthemliberty.org": 1,
                               "www.atlascircle.com": 1, "objectivism.au": 1, "aynrandcentre.au": 1, "aynrandinstitute.ca": 1,
                               "aynrandlatam.org": 1, "aynrandjapan.org": 1, "www.aynrand.org.il": 1, "www.aynrand.ph": 1, "aynrand.fr": 1,
                               "www.aynrand.de": 1, "www.objektivisme.no": 1, "www.objectivism.co.uk": 1, "objectivism.ru": 1,
                               "objetivismo.com.br": 1, "objetivismo.org": 1, "www.objektivisten.org": 1, "www.rationalendeavour.com": 1,
                               "thecultureofreasoncenter.com": 1, "wethelivingmovie.com": 1, "www.atlasshruggedmovie.com": 1,
                               "peikofflibrary.com": 1, "checkingpremises.org": 1, "ariwatch.com": 1, "freeobjectivistbooks.org": 1,
                               "tafol.org": 1, "objectivismseminar.com": 1, "www.hbletter.com": 1, "www.networkforafreesociety.com": 1,
                               "ruleofreason.blogspot.com": 1, "gusvanhorn.blogspot.com": 1, "mindofaynrand.wordpress.com": 1,
                               "barbarabranden.com": 1, "chrismatthewsciabarra.com": 1, "marsha-familaro-enright.com": 1,
                               "www.novelphilosophy.academy": 1, "www.libertarianism.org": 2, "reason.com": 3, "www.hoover.org": 1,
                               "iea.org.uk": 1, "legalizingprivacy.substack.com": 4, "bitsnbytes.blog": 1, "solohq.org": 1,
                               "rebirthofreason.com": 1, "objectivistanswers.com": 1, "iamobjectivist.com": 1,
                               "www.irreplaceable-spark.com": 1, "scottholleran.substack.com": 1, "rachewsky.substack.com": 1,
                               "stewartmargolis.substack.com": 1, "thelivingego.substack.com": 1, "prophetofcausation.substack.com": 1,
                               "objectobot.substack.com": 1, "aynrandcentre.substack.com": 1, "raymondniles.substack.com": 1,
                               "enb.substack.com": 1, "tomminc.substack.com": 1, "edscriver.substack.com": 1, "alexepstein.substack.com": 1,
                               "equaltoreality.substack.com": 1, "andersingemarson.substack.com": 1, "chrismatthewsciabarra.substack.com": 1,
                               "briancarterobjectivist.substack.com": 1, "theromanticobserver.substack.com": 1,
                               "reasonmagazine.substack.com": 1, "objectivist.substack.com": 1, "objectivistobjections.substack.com": 1,
                               "reasonforliving.substack.com": 1, "theendeavourist.substack.com": 1, "ileneskeen.substack.com": 1,
                               "theatlassocietyltd.substack.com": 1, "anthemism.substack.com": 1, "americanobjectivist.substack.com": 1,
                               "objectivisme.substack.com": 1, "jamiehmiller.substack.com": 1, "jonhersey.substack.com": 1,
                               "statesmenacademy.substack.com": 1, "luctravers.substack.com": 1, "atlasshrugged80.substack.com": 1,
                               "voicesofliberty.substack.com": 1, "novelvirtue.substack.com": 1, "brainsmatter.substack.com": 1,
                               "dontletitgo.substack.com": 1, "appliedlibertarian.substack.com": 1, "kurtkeefner.substack.com": 1},
                   "queries": ["{t}", "{t} explained", "{t} summary", "{t} quotes", "what is {t}", "{t} podcast"],
                   "topics": ["objectivism", "Ayn Rand", "Atlas Shrugged", "The Fountainhead", "Anthem novella", "We the Living",
                              "rational egoism", "the virtue of selfishness", "capitalism the unknown ideal", "individual rights",
                              "objectivist epistemology", "Leonard Peikoff", "Harry Binswanger", "Yaron Brook", "John Galt",
                              "Atlas Society events", "free market economics", "reason and individualism"]},
    "AI tools": {"sites": {"chatgpt.com": 6, "openai.com": 4, "claude.ai": 5, "www.anthropic.com": 3, "gemini.google.com": 4,
                           "chat.mistral.ai": 3, "mistral.ai": 2, "www.perplexity.ai": 4, "huggingface.co": 5,
                           "copilot.microsoft.com": 2, "grok.com": 2, "www.deepseek.com": 2, "cohere.com": 1,
                           "ai.meta.com": 2, "ollama.com": 2, "lmarena.ai": 2, "www.linkedin.com": 3,
                           "www.linkedin.com/feed/": 2, "www.linkedin.com/jobs/": 2},
                 "queries": ["{t}", "{t} explained", "best {t}", "{t} vs", "how does {t} work"],
                 "topics": ["large language models", "prompt engineering", "open weight models", "AI coding assistants",
                            "retrieval augmented generation", "AI agents", "fine tuning", "model context protocol",
                            "AI safety research", "local LLM", "speech to text", "image generation"]},
    "Web 2.0": {"sites": {"www.reddit.com": 10, "www.youtube.com": 10, "medium.com": 4, "substack.com": 3, "www.quora.com": 3,
                               "www.pinterest.com": 3, "www.tumblr.com": 2, "imgur.com": 3, "www.twitch.tv": 3, "open.spotify.com": 4,
                               "stackoverflow.com": 5, "github.com": 5, "news.ycombinator.com": 5, "www.linkedin.com": 3,
                               "www.flickr.com": 1, "www.goodreads.com": 3, "www.yelp.com": 3, "www.etsy.com": 3, "www.ebay.com": 4,
                               "www.craigslist.org": 2, "www.wikihow.com": 3, "www.instructables.com": 2, "archive.org": 4,
                               "www.duolingo.com": 2, "www.netflix.com": 2, "www.hulu.com": 1, "www.zillow.com": 2, "www.airbnb.com": 2,
                               "www.indeed.com": 2, "www.glassdoor.com": 1, "www.nextdoor.com": 1, "www.patreon.com": 2,
                               "www.kickstarter.com": 1, "www.shopify.com": 1, "www.dropbox.com": 1, "www.notion.so": 2, "www.figma.com": 1,
                               "www.canva.com": 2, "www.trello.com": 1, "slack.com": 1, "discord.com": 2, "www.paypal.com": 2,
                               "www.last.fm": 1, "soundcloud.com": 2, "bandcamp.com": 2, "letterboxd.com": 2, "www.strava.com": 1,
                               "www.meetup.com": 2},
                "queries": ["{t}", "{t} reddit", "{t} youtube", "best {t}", "{t} reviews", "how to {t}"],
                "topics": ["lofi playlist", "sourdough starter", "standing desk", "mechanical keyboard", "cheap flights", "used bike",
                           "home workout", "language learning", "board game night", "vintage camera", "retro games", "houseplants",
                           "podcast recommendations", "free fonts", "sci-fi short stories", "budget travel", "3d printing", "chess openings"]},
    "Wikipedia": {"sites": {"en.wikipedia.org/wiki/Python_(programming_language)": 1, "en.wikipedia.org/wiki/Tor_(network)": 1,
                               "en.wikipedia.org/wiki/Linear_regression": 1, "en.wikipedia.org/wiki/Bayes%27_theorem": 1,
                               "en.wikipedia.org/wiki/Random_forest": 1, "en.wikipedia.org/wiki/Ayn_Rand": 1,
                               "en.wikipedia.org/wiki/Objectivism": 1, "en.wikipedia.org/wiki/Atlas_Shrugged": 1,
                               "en.wikipedia.org/wiki/The_Fountainhead": 1, "en.wikipedia.org/wiki/Aristotle": 1,
                               "en.wikipedia.org/wiki/Capitalism": 1, "en.wikipedia.org/wiki/John_Locke": 1,
                               "en.wikipedia.org/wiki/Free_market": 1, "en.wikipedia.org/wiki/Cryptography": 1,
                               "en.wikipedia.org/wiki/Public-key_cryptography": 1, "en.wikipedia.org/wiki/Encryption": 1,
                               "en.wikipedia.org/wiki/Privacy": 1, "en.wikipedia.org/wiki/Information_privacy": 1,
                               "en.wikipedia.org/wiki/Internet_privacy": 1, "en.wikipedia.org/wiki/Machine_learning": 1,
                               "en.wikipedia.org/wiki/Neural_network": 1, "en.wikipedia.org/wiki/Gradient_descent": 1,
                               "en.wikipedia.org/wiki/Statistics": 1, "en.wikipedia.org/wiki/Normal_distribution": 1,
                               "en.wikipedia.org/wiki/Central_limit_theorem": 1, "en.wikipedia.org/wiki/Linux": 1,
                               "en.wikipedia.org/wiki/Debian": 1, "en.wikipedia.org/wiki/Open-source_software": 1,
                               "en.wikipedia.org/wiki/Git": 1, "en.wikipedia.org/wiki/SQL": 1, "en.wikipedia.org/wiki/World_Wide_Web": 1,
                               "en.wikipedia.org/wiki/Hypertext_Transfer_Protocol": 1, "en.wikipedia.org/wiki/Domain_Name_System": 1,
                               "en.wikipedia.org/wiki/Tails_(operating_system)": 1, "en.wikipedia.org/wiki/The_Tor_Project": 1,
                               "en.wikipedia.org/wiki/Mathematics": 1, "en.wikipedia.org/wiki/Calculus": 1,
                               "en.wikipedia.org/wiki/Physics": 1, "en.wikipedia.org/wiki/Chemistry": 1, "en.wikipedia.org/wiki/Biology": 1,
                               "en.wikipedia.org/wiki/Astronomy": 1, "en.wikipedia.org/wiki/Moon": 1,
                               "en.wikipedia.org/wiki/Solar_System": 1, "en.wikipedia.org/wiki/Roman_Empire": 1,
                               "en.wikipedia.org/wiki/Ancient_Greece": 1, "en.wikipedia.org/wiki/Renaissance": 1,
                               "en.wikipedia.org/wiki/Industrial_Revolution": 1, "en.wikipedia.org/wiki/American_Revolution": 1,
                               "en.wikipedia.org/wiki/World_War_II": 1, "en.wikipedia.org/wiki/Cold_War": 1,
                               "en.wikipedia.org/wiki/Chess": 1, "en.wikipedia.org/wiki/Jazz": 1, "en.wikipedia.org/wiki/Classical_music": 1,
                               "en.wikipedia.org/wiki/Impressionism": 1, "en.wikipedia.org/wiki/Architecture": 1,
                               "en.wikipedia.org/wiki/Coffee": 1, "en.wikipedia.org/wiki/Tea": 1, "en.wikipedia.org/wiki/Bread": 1,
                               "en.wikipedia.org/wiki/Pizza": 1, "en.wikipedia.org/wiki/Olive_oil": 1, "en.wikipedia.org/wiki/Cat": 1,
                               "en.wikipedia.org/wiki/Dog": 1, "en.wikipedia.org/wiki/Honey_bee": 1, "en.wikipedia.org/wiki/Oak": 1,
                               "en.wikipedia.org/wiki/Mount_Everest": 1, "en.wikipedia.org/wiki/Pacific_Ocean": 1,
                               "en.wikipedia.org/wiki/Amazon_River": 1, "en.wikipedia.org/wiki/Sahara": 1,
                               "en.wikipedia.org/wiki/Iceland": 1, "en.wikipedia.org/wiki/Japan": 1, "en.wikipedia.org/wiki/Brazil": 1,
                               "en.wikipedia.org/wiki/Canada": 1, "en.wikipedia.org/wiki/New_York_City": 1, "en.wikipedia.org/wiki/Paris": 1,
                               "en.wikipedia.org/wiki/London": 1, "en.wikipedia.org/wiki/Tokyo": 1, "en.wikipedia.org/wiki/Cycling": 1,
                               "en.wikipedia.org/wiki/Marathon": 1, "en.wikipedia.org/wiki/Football": 1,
                               "en.wikipedia.org/wiki/Olympic_Games": 1, "en.wikipedia.org/wiki/Photography": 1,
                               "en.wikipedia.org/wiki/Typography": 1, "en.wikipedia.org/wiki/Film": 1, "en.wikipedia.org/wiki/Television": 1,
                               "en.wikipedia.org/wiki/Novel": 1, "en.wikipedia.org/wiki/Poetry": 1, "en.wikipedia.org/wiki/Philosophy": 1,
                               "en.wikipedia.org/wiki/Epistemology": 1, "en.wikipedia.org/wiki/Ethics": 1, "en.wikipedia.org/wiki/Logic": 1,
                               "en.wikipedia.org/wiki/Economics": 1, "en.wikipedia.org/wiki/Supply_and_demand": 1,
                               "en.wikipedia.org/wiki/Inflation": 1, "en.wikipedia.org/wiki/Stock_market": 1,
                               "en.wikipedia.org/wiki/Bitcoin": 1, "en.wikipedia.org/wiki/Blockchain": 1,
                               "en.wikipedia.org/wiki/Electric_vehicle": 1, "en.wikipedia.org/wiki/Solar_power": 1,
                               "en.wikipedia.org/wiki/Nuclear_power": 1},
                  "queries": ["{t} wikipedia", "{t}", "what is {t}", "history of {t}"],
                  "topics": ["roman empire", "photosynthesis", "stoicism", "bitcoin", "bayes theorem", "jazz history", "ancient greece",
                             "solar system", "the renaissance", "public key cryptography", "industrial revolution", "linux kernel"]},
    "News": {"sites": ["reuters.com", "apnews.com", "bbc.com", "npr.org", "theguardian.com", "aljazeera.com",
                       "dw.com", "pbs.org"],
             "queries": ["latest {t} news", "{t} update today", "what happened with {t}", "{t} explained"],
             "topics": ["election results", "climate summit", "interest rates", "trade talks", "space launch",
                        "supreme court ruling", "wildfire", "transit strike"]},
    "Technology": {"sites": ["arstechnica.com", "theverge.com", "wired.com", "engadget.com", "cnet.com",
                             "tomshardware.com", "stackoverflow.com", "news.ycombinator.com"],
                   "queries": ["best {t} 2026", "{t} review", "how to set up {t}", "{t} vs alternatives"],
                   "topics": ["mechanical keyboard", "mesh wifi", "laptop for students", "noise cancelling headphones",
                              "home server", "password manager", "external ssd", "4k monitor"]},
    "Cooking": {"sites": ["allrecipes.com", "seriouseats.com", "bonappetit.com", "simplyrecipes.com",
                          "kingarthurbaking.com", "foodnetwork.com", "epicurious.com", "budgetbytes.com"],
                "queries": ["easy {t} recipe", "how to make {t}", "{t} without oven", "best {t} tips"],
                "topics": ["sourdough bread", "chicken curry", "banana bread", "vegetable soup", "pancakes",
                           "lasagna", "stir fry", "chocolate chip cookies"]},
    "Gardening": {"sites": ["gardeningknowhow.com", "rhs.org.uk", "almanac.com", "thespruce.com", "bhg.com",
                            "extension.umn.edu", "gardenersworld.com", "johnnyseeds.com"],
                  "queries": ["when to plant {t}", "how to grow {t}", "{t} care tips", "{t} pests"],
                  "topics": ["tomatoes", "garlic", "roses", "herbs indoors", "potatoes", "raised beds",
                             "hydrangeas", "strawberries"]},
    "Fitness": {"sites": ["runnersworld.com", "healthline.com", "verywellfit.com", "strava.com", "mayoclinic.org",
                          "menshealth.com", "womenshealthmag.com", "nerdfitness.com"],
                "queries": ["{t} for beginners", "{t} routine", "how often should i do {t}", "{t} benefits"],
                "topics": ["running", "stretching", "yoga", "cycling", "strength training", "swimming",
                           "walking", "pilates"]},
    # Everyday life: what almost everyone also does. Mixed into the Data scientist persona so it isn't all data science.
    "Everyday": {"sites": {"mail.google.com": 12, "outlook.live.com": 8, "outlook.office.com": 3, "www.youtube.com": 8,
                           "maps.google.com": 5, "en.wikipedia.org": 5, "www.amazon.com": 5, "calendar.google.com": 3,
                           "drive.google.com": 3, "news.google.com": 3, "www.weather.com": 3, "www.reddit.com": 3,
                           "www.imdb.com": 2, "www.bbc.com": 2, "www.walmart.com": 2, "www.target.com": 1},
                 "queries": ["{t} near me", "best {t}", "{t} reviews", "{t} price", "how to choose {t}",
                             "what time does {t} open", "weather this weekend", "is {t} worth it"],
                 "topics": ["pizza", "coffee shop", "running shoes", "headphones", "laptop deals", "movie times",
                            "birthday gift ideas", "hair salon", "grocery delivery", "bike shop", "train schedule",
                            "air fryer", "backpack", "thai food", "phone case", "board games"]},
    "Travel": {"sites": ["tripadvisor.com", "lonelyplanet.com", "booking.com", "kayak.com", "skyscanner.com",
                         "rick-steves.com", "cntraveler.com", "nomadicmatt.com"],
               "queries": ["things to do in {t}", "best time to visit {t}", "{t} itinerary", "cheap flights to {t}"],
               "topics": ["lisbon", "kyoto", "vancouver", "edinburgh", "mexico city", "copenhagen",
                          "new orleans", "seoul"]},
    "Personal finance": {"sites": ["nerdwallet.com", "investopedia.com", "bankrate.com", "fool.com",
                                   "morningstar.com", "consumerfinance.gov", "marketwatch.com", "kiplinger.com"],
                         "queries": ["{t} explained", "how does {t} work", "best {t} 2026", "{t} calculator"],
                         "topics": ["index funds", "high yield savings", "credit score", "mortgage rates",
                                    "budgeting app", "roth ira", "emergency fund", "car insurance"]},
    "Science": {"sites": ["nature.com", "sciencedaily.com", "space.com", "scientificamerican.com", "phys.org",
                          "newscientist.com", "nasa.gov", "quantamagazine.org"],
                "queries": ["how does {t} work", "latest discoveries in {t}", "{t} explained simply", "what is {t}"],
                "topics": ["black holes", "crispr", "fusion energy", "exoplanets", "quantum computing",
                           "ocean currents", "volcanoes", "dinosaurs"]},
    "Movies & TV": {"sites": ["imdb.com", "rottentomatoes.com", "metacritic.com", "vulture.com", "variety.com",
                              "avclub.com", "letterboxd.com", "tvguide.com"],
                    "queries": ["{t} review", "{t} ending explained", "best {t} of the year", "{t} release date"],
                    "topics": ["sci-fi movies", "documentaries", "crime series", "animated films", "sitcoms",
                               "thrillers", "fantasy shows", "period dramas"]},
    "Sports": {"sites": ["espn.com", "cbssports.com", "bbc.com", "theathletic.com", "nba.com", "nfl.com",
                         "mlb.com", "skysports.com"],
               "queries": ["{t} scores", "{t} schedule", "{t} standings", "{t} highlights"],
               "topics": ["premier league", "nba", "nfl", "tennis", "formula 1", "mlb", "cycling tour", "rugby"]},
    "Home & DIY": {"sites": ["familyhandyman.com", "thisoldhouse.com", "homedepot.com", "lowes.com",
                             "apartmenttherapy.com", "hgtv.com", "ikea.com", "bobvila.com"],
                   "queries": ["how to fix {t}", "diy {t}", "{t} cost", "best {t} for small spaces"],
                   "topics": ["leaky faucet", "drywall hole", "shelves", "squeaky door", "paint a room",
                              "storage ideas", "window insulation", "deck stain"]},
    "Books": {"sites": ["goodreads.com", "bookshop.org", "theguardian.com", "lithub.com", "kirkusreviews.com",
                        "openlibrary.org", "penguinrandomhouse.com", "audible.com"],
              "queries": ["best {t} books", "{t} book recommendations", "books like {t}", "{t} reading list"],
              "topics": ["mystery", "historical fiction", "science fiction", "biography", "fantasy",
                         "self help", "poetry", "classic novels"]},
}


_REAL: dict[str, list[str]] = {}


def real_queries(theme: str) -> list[str]:
    """Real people's searches on a theme, picked out of MS MARCO (Bing) and GooAQ (Google)
    by tools/build_theme_queries.py and shipped in data/themes/."""
    if theme not in _REAL:
        import gzip
        from .paths import resource_root
        slug = theme.lower().replace(" & ", "_").replace(" ", "_")
        try:
            with gzip.open(resource_root() / "data" / "themes" / f"{slug}.txt.gz", "rt", encoding="utf-8") as fh:
                _REAL[theme] = [ln.strip() for ln in fh if ln.strip()]
        except OSError:
            _REAL[theme] = []
    return _REAL[theme]


def _pick_site(rng: random.Random, sites) -> str:
    """Sites are a list (all equal) or {site: how popular}; popular ones come up more often."""
    if isinstance(sites, dict):
        # Popular sites come up more often, but gently (square root), so a big list is not dominated by a few.
        return rng.choices(list(sites), weights=[w ** 0.5 for w in sites.values()])[0]
    return rng.choice(sites)


def _pick_query(rng: random.Random, theme: str, real_share: float = 0.8) -> str:
    """Mostly a real person's search on the theme; otherwise one made from the theme's topics."""
    real = real_queries(theme)
    if real and rng.random() < real_share:
        return rng.choice(real)
    cat = CATEGORIES[theme]
    return rng.choice(cat["queries"]).format(t=rng.choice(cat["topics"]))


def query_for_site(rng: random.Random, site: str) -> str | None:
    """A topical search a person might make that leads to this site (never just the site's name), or None."""
    import urllib.parse as _u
    s = site.lower().removeprefix("www.").rstrip("/")
    if s.startswith("en.wikipedia.org/wiki/"):
        title = _u.unquote(site.split("/wiki/", 1)[1].rstrip("/")).replace("_", " ")
        if ":" in title:                                  # Special:Random and the like are not something to search for
            return None
        return rng.choice([f"{title} wikipedia", title, f"what is {title}", f"{title} history"])
    for theme, cat in CATEGORIES.items():
        if any(k.lower().removeprefix("www.").rstrip("/") == s for k in cat["sites"]):
            return _pick_query(rng, theme)
    return None


class Interests:
    """The active themes right now, and sites and searches drawn from them."""

    def __init__(self, rng: random.Random, allowed: list[str] | None = None, active: int = 3,
                 rotate_days: float = 10, salt: str = "", clock=time.time):
        self.rng, self.clock, self.salt = rng, clock, salt or "default"
        self.allowed = [c for c in (allowed or list(CATEGORIES)) if c in CATEGORIES] or list(CATEGORIES)
        self.active_n = max(1, min(int(active), len(self.allowed)))
        self.rotate_days = max(1.0, float(rotate_days))

    def active(self) -> list[str]:
        period = int(self.clock() // (self.rotate_days * 86400))
        seed = hashlib.sha256(f"{self.salt}:{period}".encode()).hexdigest()
        return random.Random(seed).sample(sorted(self.allowed), self.active_n)

    def site(self) -> str:
        return _pick_site(self.rng, CATEGORIES[self.rng.choice(self.active())]["sites"])

    def query(self) -> str:
        return _pick_query(self.rng, self.rng.choice(self.active()))


# A persona is who the noise mostly looks like: a fixed mix of themes. It's followed
# "mostly" (Settings sets how much); the rest of the noise stays varied.
PERSONAS: dict[str, dict[str, float]] = {
    "Data scientist": {"Data science": 0.85, "Everyday": 0.15},     # mostly data science, plus everyday life
    # Ason: part data scientist, part ordinary web user (Web 2.0, Wikipedia, everyday), part Objectivist.
    "Ason": {"Data science": 0.20, "Everyday": 0.13, "Web 2.0": 0.14, "Wikipedia": 0.09, "Objectivism": 0.14,
             "AI tools": 0.09, "Technology": 0.08, "News": 0.05, "Books": 0.05, "Science": 0.03},
    "Developer": {"Technology": 0.6, "Data science": 0.2, "Science": 0.1, "Books": 0.1},
    "Sports fan": {"Sports": 0.7, "Fitness": 0.15, "Movies & TV": 0.15},
    "Student": {"Science": 0.3, "Books": 0.25, "Technology": 0.2, "Movies & TV": 0.15, "Personal finance": 0.1},
    "Home cook and gardener": {"Cooking": 0.5, "Gardening": 0.35, "Home & DIY": 0.15},
    "Traveller": {"Travel": 0.6, "News": 0.15, "Cooking": 0.15, "Personal finance": 0.1},
}


class Persona:
    """Same interface as Interests (site, query, active), from a fixed weighted theme mix."""

    def __init__(self, rng: random.Random, name: str):
        self.rng, self.name = rng, name
        self.mix = PERSONAS.get(name, {})

    def active(self) -> list[str]:
        return list(self.mix)

    def _theme(self) -> str:
        return self.rng.choices(list(self.mix), weights=list(self.mix.values()))[0]

    def site(self) -> str:
        return _pick_site(self.rng, CATEGORIES[self._theme()]["sites"])

    def query(self) -> str:
        return _pick_query(self.rng, self._theme())
