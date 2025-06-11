#pragma once

#include <functional>
#include <vector>

#include "parallel/parallel.h"

template <typename T>
void VectorMul(std::vector<T>& c, std::vector<T> const& a, T const& b) {
  c.resize(a.size());
  auto parallel_f = [&c, &a, &b](size_t i) { c[i] = a[i] * b; };
  parallel::For(a.size(), parallel_f);
}

template <typename T>
void VectorMul(std::vector<T>& c, int64_t n,
               std::function<T const&(int64_t)>& get_a, T const& b) {
  c.resize(n);
  auto parallel_f = [&c, &get_a, &b](size_t i) { c[i] = get_a(i) * b; };
  parallel::For(n, parallel_f);
}

template <typename T>
void VectorAdd(std::vector<T>& c, std::vector<T> const& a, T const& b) {
  c.resize(a.size());
  auto parallel_f = [&c, &a, &b](size_t i) { c[i] = a[i] + b; };
  parallel::For(c.size(), parallel_f);
}

template <typename T>
void VectorAdd(std::vector<T>& c, int64_t n,
               std::function<T const&(int64_t)>& get_a, T const& b) {
  c.resize(n);
  auto parallel_f = [&c, &get_a, &b](size_t i) { c[i] = get_a(i) + b; };
  parallel::For(c.size(), parallel_f);
}

template <typename T>
void VectorAdd(std::vector<T>& c, std::vector<T> const& a,
               std::vector<T> const& b) {
  auto const& aa = a.size() >= b.size() ? a : b; //max
  auto const& bb = a.size() >= b.size() ? b : a; //min

  c.resize(aa.size());
  auto parallel_f = [&c, &aa, &bb](size_t i) {
    if (i < bb.size()) {
      c[i] = aa[i] + bb[i];
    } else {
      c[i] = aa[i];
    }
  };
  parallel::For(aa.size(), parallel_f);
}

template <typename T>
void VectorAdd(std::vector<T>& c, int64_t n,
               std::function<T const&(int64_t)>& get_a,
               std::function<T const&(int64_t)>& get_b) {
  c.resize(n);
  auto parallel_f = [&c, &get_a, &get_b](size_t i) {
    c[i] = get_a[i] + get_b[i]; 
  };
  parallel::For(n, parallel_f);
}

template <typename T>
void VectorInc(std::vector<T>& a, std::vector<T> const& b) {
  VectorAdd(a, a, b);
}

template <typename T>
void VectorInc(std::vector<T>& a, T const& b) {
  VectorAdd(a, a, b);
}

template <typename T>
std::vector<std::vector<T>> operator*(std::vector<std::vector<T>> const& a, T const& b) {
  std::vector<std::vector<T>> c(a.size(), std::vector<T>(a[0].size()));
  auto parallel_f = [&c, &a, &b](size_t i) {
    int row = i / a[0].size(), col = i % a[0].size();
    c[row][col] = a[row][col] * b;
  };
  parallel::For(a.size()*a[0].size(), parallel_f);
  return c;
}

template <typename T>
std::vector<T> operator*(std::vector<T> const& a, T const& b) {
  std::vector<T> c;
  VectorMul(c, a, b);
  return c;
}

std::vector<G1> operator*(std::vector<G1> const& a, Fr const& b) {
  std::vector<G1> c;
  c.resize(a.size());
  auto parallel_f = [&c, &a, &b](size_t i) { c[i] = a[i] * b; };
  parallel::For(a.size(), parallel_f);
  return c;
}

template <typename T>
std::vector<T>& operator*=(std::vector<T>& a, T const& b) {
  VectorMul(a, a, b);
  return a;
}

template <typename T>
std::vector<T> operator+(std::vector<T> const& a, T const& b) {
  std::vector<T> c;
  VectorAdd(c, a, b);
  return c;
}

template <typename T>
std::vector<T>& operator+=(std::vector<T>& a, T const& b) {
  VectorAdd(a, a, b);
  return a;
}

template <typename T>
std::vector<T> operator+(std::vector<T> const& a, std::vector<T> const& b) {
  std::vector<T> c;
  VectorAdd(c, a, b);
  return c;
}

template <typename T>
std::vector<T> operator-(std::vector<T> const& a, std::vector<T> const& b) {
  assert(a.size() == b.size());
  std::vector<T> c;
  auto const& aa = a.size() >= b.size() ? a : b; //max
  auto const& bb = a.size() >= b.size() ? b : a; //min

  c.resize(aa.size());
  auto parallel_f = [&c, &aa, &bb](size_t i) {
    if (i < bb.size()) {
      c[i] = aa[i] - bb[i];
    } else {
      c[i] = -aa[i];
    }
  };
  parallel::For(aa.size(), parallel_f);
  return c;
}

template <typename T>
std::vector<T>& operator+=(std::vector<T>& a, std::vector<T> const& b) {
  VectorAdd(a, a, b);
  return a;
}

template <typename T>
std::vector<T> operator-(std::vector<T> const& a) {
  std::vector<T> c(a.size());
  auto parallel_f = [&c, &a](size_t i) {
    c[i] = -a[i]; 
  };
  parallel::For(c.size(), parallel_f);  // n < 16 * 1024);
  return c;
}
