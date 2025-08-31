/** @file
 *****************************************************************************

 Imeplementation of interfaces for evaluation domains.

 See evaluation_domain.hpp .

 We currently implement, and select among, three types of domains:
 - "basic radix-2": the domain has size m = 2^k and consists of the m-th roots of unity
 - "extended radix-2": the domain has size m = 2^{k+1} and consists of "the m-th roots of unity" union "a coset"
 - "step radix-2": the domain has size m = 2^k + 2^r and consists of "the 2^k-th roots of unity" union "a coset of 2^r-th roots of unity"

 *****************************************************************************
 * @author     This file is part of libfqfft, developed by SCIPR Lab
 *             and contributors (see AUTHORS).
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/

#ifndef GET_EVALUATION_DOMAIN_TCC_
#define GET_EVALUATION_DOMAIN_TCC_

#include <libff/common/profiling.hpp>
#include <libfqfft/evaluation_domain/domains/arithmetic_sequence_domain.hpp>
#include <libfqfft/evaluation_domain/domains/basic_radix2_domain.hpp>
#include <libfqfft/evaluation_domain/domains/extended_radix2_domain.hpp>
#include <libfqfft/evaluation_domain/domains/geometric_sequence_domain.hpp>
#include <libfqfft/evaluation_domain/domains/step_radix2_domain.hpp>
#include <libfqfft/evaluation_domain/evaluation_domain.hpp>
#include <libfqfft/tools/exceptions.hpp>

namespace libfqfft {

template<typename FieldT>
std::shared_ptr<evaluation_domain<FieldT> > get_evaluation_domain(const size_t min_size)
{
    libff::enter_block("Call to get_evaluation_domain");
    std::shared_ptr<evaluation_domain<FieldT> > result;

    const size_t big = ((size_t)1) <<(libff::log2(min_size)-1);
    const size_t small = min_size - big;
    const size_t rounded_small = (((size_t)1) <<libff::log2(small));

    result = basic_radix2_domain<FieldT>::create_ptr(min_size);
    if (!result) result = extended_radix2_domain<FieldT>::create_ptr(min_size);
    if (!result) result = step_radix2_domain<FieldT>::create_ptr(min_size);
    if (!result) result = basic_radix2_domain<FieldT>::create_ptr(big + rounded_small);
    if (!result) result = extended_radix2_domain<FieldT>::create_ptr(big + rounded_small);
    if (!result) result = step_radix2_domain<FieldT>::create_ptr(big + rounded_small);
    if (!result) result = geometric_sequence_domain<FieldT>::create_ptr(min_size);
    if (!result) result = arithmetic_sequence_domain<FieldT>::create_ptr(min_size);

    if (!result) {
      std::cerr << "oops: get_evaluation_domain: no matching domain " << min_size << "\n";
      throw DomainSizeException("get_evaluation_domain: no matching domain");
    }

    if (!libff::inhibit_profiling_info) {
      std::cout << "get_evaluation_domain(" << min_size << ")"
                << " " << result->m << "\n";
    }
    libff::leave_block("Call to get_evaluation_domain");

    return result;

#if 0
    try { result.reset(new basic_radix2_domain<FieldT>(min_size)); }
    catch(...) { try { result.reset(new extended_radix2_domain<FieldT>(min_size)); }
    catch(...) { try { result.reset(new step_radix2_domain<FieldT>(min_size)); }
    catch(...) { try { result.reset(new basic_radix2_domain<FieldT>(big + rounded_small)); }
    catch(...) { try { result.reset(new extended_radix2_domain<FieldT>(big + rounded_small)); }
    catch(...) { try { result.reset(new step_radix2_domain<FieldT>(big + rounded_small)); }
    catch(...) { try { result.reset(new geometric_sequence_domain<FieldT>(min_size)); }
    catch(...) { try { result.reset(new arithmetic_sequence_domain<FieldT>(min_size)); }
    catch(...) { throw DomainSizeException("get_evaluation_domain: no matching domain"); }}}}}}}}
    return result;
#endif
}

} // libfqfft

#endif // GET_EVALUATION_DOMAIN_TCC_
