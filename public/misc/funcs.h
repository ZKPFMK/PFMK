#pragma once

#include "./types.h"
#include "public.h"

#ifdef __APPLE__
#include <sys/resource.h>
#endif

namespace misc {
inline void BuildR(std::vector<Fr>& s, std::vector<Fr> const& r){
  // Tick tick(__FN__, std::to_string(r.size()) + " " + std::to_string(s.size()));
  s[0] = 1;
  for (size_t i = 0; i < r.size(); ++i) {
    for(int j=(1 << i) - 1; j>=0; j--){ //j可能为负数
      int lf = (j << 1), rt = lf + 1;
      if(lf >= s.size()) continue;
      else {
        //注意, 顺序不可以颠倒, 先r后l
        if(rt < s.size()){
            s[rt] = s[j] * r[i];
        }
        s[lf] = s[j] * (1 - r[i]);
      }
    }
  }
}

inline std::vector<Fr> BuildE(std::vector<Fr> const& e, bool reverse=false){
  // Tick tick(__FN__, std::to_string(e.size()));
  std::vector<Fr> s(1 << e.size());
  s[0] = 1;
  if(!reverse){
    for (size_t i = 0; i < e.size(); ++i) {
      for(int j=(1 << i) - 1; j>=0; j--){
        int l = (j << 1), r = l + 1;
        s[r] = s[j] * e[i];
        s[l] = s[j];
      }
    }
  }else{
    for (size_t i = 0; i < e.size(); ++i) {
      for(int j=(1 << i)-1; j>=0; j--){
        int l = (j << 1), r = l + 1;
        s[r] = s[j];
        s[l] = s[j] * e[i];
      }
    }
  }
  return s;
}

// left * 1, right * e
inline void BuildE(std::vector<Fr>& s, std::vector<Fr> const& e, bool reverse=false){
  // Tick tick(__FN__, std::to_string(e.size()) + " " + std::to_string(s.size()));
  s[0] = 1;
  if(!reverse){
    for (size_t i = 0; i < e.size(); ++i) {
      for(int j=(1 << i) - 1; j>=0; j--){
        int l = (j << 1), r = l + 1;
        if(l >= s.size()) continue;
        else {
          //注意, 顺序不可以颠倒, 先r后l
          if(r < s.size()){
              s[r] = s[j] * e[i];
          }
          s[l] = s[j];
        }
      }
    }
  }else{
    for (size_t i = 0; i < e.size(); ++i) {
      for(int j=(1 << i)-1; j>=0; j--){
        int l = (j << 1), r = l + 1;
        if(l >= s.size()) continue;
        else {
          //注意, 顺序不可以颠倒, 先r后l
          if(r < s.size()){
              s[r] = s[j];
          }
          s[l] = s[j] * e[i];
        }
      }
    }
  }
}

// Compute the "acute" tensor product: otimes_{i=0}^{k-1} (1, e[i])
  // Result has size 2^k
static void ComputeAcuteTensor(std::vector<Fr>& result,
                              std::vector<Fr> const& challenges,
                              int64_t start, int64_t count) {
  int64_t size = 1LL << count;
  result.resize(size);
  result[0] = Fr(1);
  for (int64_t i = 0; i < count; ++i) {
    int64_t half = 1LL << i;
    for (int64_t j = half - 1; j >= 0; --j) {
      result[2 * j + 1] = result[j] * challenges[start + i];
      result[2 * j] = result[j];
    }
  }
}

inline std::string HexToStr(void const* p, size_t len) {
  std::string ret;
  ret.reserve(len * 4);
  char buf[4];
  uint8_t const* q = (uint8_t const*)p;
  for (size_t i = 0; i < len; ++i) {
    sprintf(buf, "%02x", q[i]);
    ret.append(buf);
  }
  return ret;
}

inline std::string HexToStr(h256_t const& h) {
  return HexToStr(h.data(), h.size());
}

inline bool StrToHex(char const* p, size_t len, uint8_t* q) {
  if (len % 2) return false;
  for (size_t i = 0; i < len / 2; ++i) {
    char buf[3];
    buf[0] = p[0];
    buf[1] = p[1];
    buf[2] = 0;
    int v = strtol(buf, NULL, 16);
    if (v > 256 || v < 0) return false;
    *q = (uint8_t)(v & 0xff);
    ++p;
    ++p;
    ++q;
  }
  return true;
}

template <size_t T>
std::array<uint8_t, T> StrToH(std::string const& s) {
  CHECK(s.size() >= T * 2, "");
  std::array<uint8_t, T> ret;
  StrToHex(s.data(), T * 2, ret.data());
  return ret;
}

inline bool StartWith(char const* p, char const* q) {
  for (;;) {
    char a = *p;
    char b = *q;
    if (!b) return true;
    if (!a) return false;
    if (a != b) return false;
    ++p;
    ++q;
  }
}

inline void HexStrToH256(std::string const& str, h256_t& h) {
  CHECK(str.size() == 32 * 2, "");
  StrToHex(str.c_str(), str.size(), h.data());
}

inline uint64_t Log2UB(uint64_t n) { //返回最小的k, 满足 2**k >= n
  assert(n);
  if (n == 1) return 0;
  if (n % 2) ++n;
  return 1 + Log2UB(n / 2);
}

inline uint64_t Pow2UB(uint64_t v) { //ret=min(2^k) >= v
  v--;
  v |= v >> 1;
  v |= v >> 2;
  v |= v >> 4;
  v |= v >> 8;
  v |= v >> 16;
  v |= v >> 32;
  v++;
  return v;
}

inline bool Str2UInt(std::string s, uint64_t* v) {
  try {
    *v = boost::lexical_cast<uint64_t>(s);
    return true;
  } catch (boost::exception&) {
    return false;
  }
}

inline bool LoadTinyFile(std::string const& filename, std::string* text) {
  typedef std::unique_ptr<FILE, decltype(&fclose)> FileUniquePtr;

  struct stat st;
  if (::stat(filename.c_str(), &st)) return false;
  std::size_t size = st.st_size;
  if (size > 1024 * 1024 * 100) return false;

  text->resize(size);
  if (size == 0) return true;

  FileUniquePtr file(std::fopen(filename.c_str(), "rb"), fclose);
  if (!file) return false;

  return fread(&(*text)[0], 1, size, file.get()) == size;
}

inline bool SaveTinyFile(std::string const& filename, void const* data,
                         size_t size) {
  typedef std::unique_ptr<FILE, decltype(&fclose)> FileUniquePtr;
  FileUniquePtr file(std::fopen(filename.c_str(), "wb"), fclose);
  if (!file) return false;
  return fwrite(data, 1, size, file.get()) == size;
}

inline bool IsSameFile(std::string const& file1, std::string const& file2) {
  try {
    io::mapped_file_params params1;
    params1.path = file1;
    params1.flags = io::mapped_file_base::readonly;
    io::mapped_file_source view1(params1);

    io::mapped_file_params params2;
    params2.path = file2;
    params2.flags = io::mapped_file_base::readonly;
    io::mapped_file_source view2(params2);

    if (view1.size() != view2.size()) return false;

    return memcmp(view1.data(), view2.data(), view1.size()) == 0;
  } catch (std::exception&) {
    return false;
  }
}

inline bool GetFileSha256(std::string const& file, h256_t& h) {
  try {
    io::mapped_file_params params;
    params.path = file;
    params.flags = io::mapped_file_base::readonly;
    io::mapped_file_source view(params);

    CryptoPP::SHA256 hash;
    hash.Update((uint8_t const*)view.data(), view.size());
    hash.Final(h.data());
    return true;
  } catch (std::exception&) {
    assert(false);
    return false;
  }
}

inline std::string RandString(size_t max_len) {
  size_t len = rand() % max_len;
  if (!len) return std::string();
  std::string ret;
  ret.reserve(len);
  for (size_t i = 0; i < len; ++i) {
    ret.push_back((char)rand());
  }
  return ret;
}

inline void PrintVector(std::vector<G1> const& a) {
  std::cout << "\n";
  for (auto const& i : a) {
    std::cout << i << "\n";
  }
  std::cout << "\n";
}

inline void PrintVector(std::vector<Fr> const& a) {
  std::cout << "[";
  for (auto const& i : a) {
    std::cout << i << ", ";
  }
  std::cout << "]\n";
}

inline void PrintVector(std::vector<std::vector<Fr>> const& a) {
  std::cout << "[\n";
  for (int i=0; i<a.size(); i++) {
    std::cout << "[";
    for(int j=0; j<a[i].size(); j++){
      std::cout << a[i][j] << ",";
    }
    std::cout << "],\n";
  }
  std::cout << "]\n";
}

template <size_t N>
void PrintArray(std::array<Fr, N> const& a) {
  std::cout << "\n";
  for (auto const& i : a) {
    std::cout << i << "\n";
  }
  std::cout << "\n";
}

/**
 * Get peak memory usage of a process by PID
 * @param pid Process ID
 * @return Peak memory usage in kB, or 0 if failed
 */
inline int GetPeakMemoryByPid(pid_t pid) {
#ifdef __linux__
  char file_name[64];
  sprintf(file_name, "/proc/%d/status", pid);

  FILE* fd = fopen(file_name, "r");
  if (!fd) return 0;

  char line_buff[512];
  int vmhwm = 0;
  while (fgets(line_buff, sizeof(line_buff), fd)) {
    if (strncmp(line_buff, "VmHWM:", 6) == 0) {
      sscanf(line_buff, "%*s %d", &vmhwm);
      break;
    }
  }
  fclose(fd);
  return vmhwm;  // kB
#elif defined(__APPLE__)
  (void)pid;
  struct rusage usage;
  if (getrusage(RUSAGE_SELF, &usage) == 0) {
    // macOS returns ru_maxrss in bytes
    return (int)(usage.ru_maxrss / 1024);  // convert to kB
  }
  return 0;
#else
  (void)pid;
  return 0;
#endif
}

/**
 * Print current process memory usage
 */
inline void PrintMemoryUsage() {
  double mb = GetPeakMemoryByPid(getpid()) / 1024.0;
  std::cout << "Process peak memory: " << mb << " MB\n";
}

}  // namespace misc
