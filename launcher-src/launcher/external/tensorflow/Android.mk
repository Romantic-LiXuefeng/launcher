SUB_PATH := external/tensorflow/tensorflow/lite

LOCAL_SRC_FILES +=  \
	$(SUB_PATH)/allocation.cc \
	$(SUB_PATH)/arena_planner.cc \
	$(SUB_PATH)/graph_info.cc \
	$(SUB_PATH)/interpreter.cc \
	$(SUB_PATH)/minimal_logging.cc \
	$(SUB_PATH)/minimal_logging_android.cc \
	$(SUB_PATH)/mmap_allocation.cc \
	$(SUB_PATH)/model.cc \
	$(SUB_PATH)/mutable_op_resolver.cc \
	$(SUB_PATH)/nnapi_delegate_disabled.cc \
	$(SUB_PATH)/optional_debug_tools.cc \
	$(SUB_PATH)/simple_memory_arena.cc \
	$(SUB_PATH)/stderr_reporter.cc \
	$(SUB_PATH)/string_util.cc \
	$(SUB_PATH)/util.cc \
	$(SUB_PATH)/c/c_api_internal.c \
	$(SUB_PATH)/core/api/error_reporter.cc \
	$(SUB_PATH)/core/api/flatbuffer_conversions.cc \
	$(SUB_PATH)/core/api/op_resolver.cc \
	$(SUB_PATH)/core/subgraph.cc \
	$(SUB_PATH)/downloads/farmhash/src/farmhash.cc \
	$(SUB_PATH)/downloads/fft2d/fftsg.c \
	$(SUB_PATH)/kernels/internal/optimized/neon_tensor_utils.cc \
	$(SUB_PATH)/kernels/internal/reference/portable_tensor_utils.cc \
	$(SUB_PATH)/kernels/internal/kernel_utils.cc \
	$(SUB_PATH)/kernels/internal/mfcc.cc \
	$(SUB_PATH)/kernels/internal/mfcc_dct.cc \
	$(SUB_PATH)/kernels/internal/mfcc_mel_filterbank.cc \
	$(SUB_PATH)/kernels/internal/quantization_util.cc \
	$(SUB_PATH)/kernels/internal/spectrogram.cc \
	$(SUB_PATH)/kernels/internal/tensor_utils.cc \
	$(SUB_PATH)/kernels/activations.cc \
	$(SUB_PATH)/kernels/add.cc \
	$(SUB_PATH)/kernels/add_n.cc \
	$(SUB_PATH)/kernels/arg_min_max.cc \
	$(SUB_PATH)/kernels/audio_spectrogram.cc \
	$(SUB_PATH)/kernels/basic_rnn.cc \
	$(SUB_PATH)/kernels/batch_to_space_nd.cc \
	$(SUB_PATH)/kernels/bidirectional_sequence_lstm.cc \
	$(SUB_PATH)/kernels/bidirectional_sequence_rnn.cc \
	$(SUB_PATH)/kernels/cast.cc \
	$(SUB_PATH)/kernels/ceil.cc \
	$(SUB_PATH)/kernels/comparisons.cc \
	$(SUB_PATH)/kernels/concatenation.cc \
	$(SUB_PATH)/kernels/conv.cc \
	$(SUB_PATH)/kernels/depthwise_conv.cc \
	$(SUB_PATH)/kernels/dequantize.cc \
	$(SUB_PATH)/kernels/detection_postprocess.cc \
	$(SUB_PATH)/kernels/div.cc \
	$(SUB_PATH)/kernels/eigen_support.cc \
	$(SUB_PATH)/kernels/elementwise.cc \
	$(SUB_PATH)/kernels/embedding_lookup.cc \
	$(SUB_PATH)/kernels/embedding_lookup_sparse.cc \
	$(SUB_PATH)/kernels/exp.cc \
	$(SUB_PATH)/kernels/expand_dims.cc \
	$(SUB_PATH)/kernels/fake_quant.cc \
	$(SUB_PATH)/kernels/fill.cc \
	$(SUB_PATH)/kernels/floor.cc \
	$(SUB_PATH)/kernels/floor_div.cc \
	$(SUB_PATH)/kernels/floor_mod.cc \
	$(SUB_PATH)/kernels/fully_connected.cc \
	$(SUB_PATH)/kernels/gather.cc \
	$(SUB_PATH)/kernels/gather_nd.cc \
	$(SUB_PATH)/kernels/gemm_support.cc \
	$(SUB_PATH)/kernels/hashtable_lookup.cc \
	$(SUB_PATH)/kernels/if.cc \
	$(SUB_PATH)/kernels/kernel_util.cc \
	$(SUB_PATH)/kernels/l2norm.cc \
	$(SUB_PATH)/kernels/local_response_norm.cc \
	$(SUB_PATH)/kernels/logical.cc \
	$(SUB_PATH)/kernels/lsh_projection.cc \
	$(SUB_PATH)/kernels/lstm.cc \
	$(SUB_PATH)/kernels/lstm_eval.cc \
	$(SUB_PATH)/kernels/matrix_diag.cc \
	$(SUB_PATH)/kernels/maximum_minimum.cc \
	$(SUB_PATH)/kernels/mfcc.cc \
	$(SUB_PATH)/kernels/mirror_pad.cc \
	$(SUB_PATH)/kernels/mul.cc \
	$(SUB_PATH)/kernels/neg.cc \
	$(SUB_PATH)/kernels/one_hot.cc \
	$(SUB_PATH)/kernels/pack.cc \
	$(SUB_PATH)/kernels/pad.cc \
	$(SUB_PATH)/kernels/pooling.cc \
	$(SUB_PATH)/kernels/pow.cc \
	$(SUB_PATH)/kernels/range.cc \
	$(SUB_PATH)/kernels/rank.cc \
	$(SUB_PATH)/kernels/reduce.cc \
	$(SUB_PATH)/kernels/register.cc \
	$(SUB_PATH)/kernels/register_ref.cc \
	$(SUB_PATH)/kernels/reshape.cc \
	$(SUB_PATH)/kernels/resize_bilinear.cc \
	$(SUB_PATH)/kernels/resize_nearest_neighbor.cc \
	$(SUB_PATH)/kernels/reverse.cc \
	$(SUB_PATH)/kernels/reverse_sequence.cc \
	$(SUB_PATH)/kernels/select.cc \
	$(SUB_PATH)/kernels/shape.cc \
	$(SUB_PATH)/kernels/skip_gram.cc \
	$(SUB_PATH)/kernels/slice.cc \
	$(SUB_PATH)/kernels/space_to_batch_nd.cc \
	$(SUB_PATH)/kernels/space_to_depth.cc \
	$(SUB_PATH)/kernels/sparse_to_dense.cc \
	$(SUB_PATH)/kernels/split.cc \
	$(SUB_PATH)/kernels/split_v.cc \
	$(SUB_PATH)/kernels/squared_difference.cc \
	$(SUB_PATH)/kernels/squeeze.cc \
	$(SUB_PATH)/kernels/strided_slice.cc \
	$(SUB_PATH)/kernels/sub.cc \
	$(SUB_PATH)/kernels/svdf.cc \
	$(SUB_PATH)/kernels/tile.cc \
	$(SUB_PATH)/kernels/topk_v2.cc \
	$(SUB_PATH)/kernels/transpose.cc \
	$(SUB_PATH)/kernels/transpose_conv.cc \
	$(SUB_PATH)/kernels/unidirectional_sequence_lstm.cc \
	$(SUB_PATH)/kernels/unidirectional_sequence_rnn.cc \
	$(SUB_PATH)/kernels/unique.cc \
	$(SUB_PATH)/kernels/unpack.cc \
	$(SUB_PATH)/kernels/where.cc \
	$(SUB_PATH)/kernels/while.cc \
	$(SUB_PATH)/kernels/zeros_like.cc