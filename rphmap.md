---
title: High dimensional density estimation with random projection histograms
author: Shrayes Ramesh
date: March 26, 2016
---

# The need for a high dimensional density estimate

## Outliers in a single dimension vs outliers in high dimensions

Given a dataset of one dimension, the simplest nonparametric approach to detecting outliers is by computing an empirical probability distribution (pdf) cheaply executed with a histogram. Observations that are located in areas without other data nearby are labeled as outliers. In one dimension, outliers could either be located at the *tails* of the distribution-- at surprisingly high or low values for that variable, or alternative they could exist in the *valleys* of an empirical pdf histogram, in between clusters of other points. Visually, both types of outliers can be flagged directly from a histogram.

To motivate the need for an algorithm to compute densities in high dimensions, now suppose we have a dataset consisting of two measurements about each observation. In two dimensions, computing an empirical pdf is still cheap. We would bin the data into a heatmap in two dimensions (a 2d histogram). Outliers are still identified by looking for points in sparsely populated regions. When comparing 2d heatmaps to 1d histograms, note  that the number of tails of the distribution has doubled, and the number of possible *valleys* or empty cells have also multiplied.

As the number of dimensions of our data increases, the curse of dimensionality takes hold-- the rapid growth of sparsity of the empirical histograms in high dimensions overtakes our ability to identify outliers using our "find points in empty space" approach. As the number of dimensions grows, points are more and more likely to be in cells all by themselves. Therefore, we need a new approach in high dimensions.

The algorithm outlined here describes a way to estimate densities of data in very high dimensions. Utilizing lessons from the theory of random projections and law of large numbers, I propose a simple, scalable approach to estimating (ordinal) density estimates in high dimensions (on a sphere).

## Random projection histograms

The high dimensional dataset consists of N points in high D dimensions, X = {x_i}_{1...N}, x_i \elem R^D$$. For meaningful distance estimates, suppose the points have been normalized to be on the unit D-1 sphere, i.e x_i / ||x_i|| = 1.

A random projection vector is a D-dimensional  
