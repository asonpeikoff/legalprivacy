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
    "Objectivism": {"sites": {"aynrand.org": 12, "atlassociety.org": 8, "aynrandlexicon.com": 5, "theobjectivestandard.com": 5,
                              "peikoff.com": 3, "aynrandbookstore.com": 2, "legalizingprivacy.substack.com": 3,
                              "goodreads.com": 2, "plato.stanford.edu": 2, "iep.utm.edu": 2},
                    "queries": ["Atlas Shrugged {t}", "Ayn Rand {t}", "Objectivism {t}", "The Fountainhead {t}",
                                "Objectivist ethics {t}", "Ayn Rand Lexicon {t}", "Leonard Peikoff {t}"],
                    "topics": ["summary", "quotes", "reading order", "rational self-interest", "individual rights",
                               "property rights", "capitalism the unknown ideal", "epistemology", "free speech",
                               "privacy and property", "lecture", "study guide", "reading group"]},
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
        return rng.choices(list(sites), weights=list(sites.values()))[0]
    return rng.choice(sites)


def _pick_query(rng: random.Random, theme: str, real_share: float = 0.8) -> str:
    """Mostly a real person's search on the theme; otherwise one made from the theme's topics."""
    real = real_queries(theme)
    if real and rng.random() < real_share:
        return rng.choice(real)
    cat = CATEGORIES[theme]
    return rng.choice(cat["queries"]).format(t=rng.choice(cat["topics"]))


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
    "Objectivist": {"Objectivism": 0.7, "Books": 0.1, "News": 0.1, "Personal finance": 0.1},
    "Objectivist data scientist": {"Objectivism": 0.45, "Data science": 0.45, "Everyday": 0.1},   # half and half
    "Developer": {"Technology": 0.6, "Data science": 0.2, "Science": 0.1, "Books": 0.1},
    "Sports fan": {"Sports": 0.7, "Fitness": 0.15, "Movies & TV": 0.15},
    "Student": {"Science": 0.3, "Books": 0.25, "Technology": 0.2, "Movies & TV": 0.15, "Personal finance": 0.1},
    "Home cook and gardener": {"Cooking": 0.5, "Gardening": 0.35, "Home & DIY": 0.15},
    "Traveller": {"Travel": 0.6, "News": 0.15, "Cooking": 0.15, "Personal finance": 0.1},
}


# Sites every persona can visit now and then, whoever the noise is pretending to be.
PERSONA_EXTRA_SITES = ["postsocialist.com"]
PERSONA_EXTRA_SHARE = 0.04


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
        if self.rng.random() < PERSONA_EXTRA_SHARE:               # every persona may also visit these
            return self.rng.choice(PERSONA_EXTRA_SITES)
        return _pick_site(self.rng, CATEGORIES[self._theme()]["sites"])

    def query(self) -> str:
        return _pick_query(self.rng, self._theme())
